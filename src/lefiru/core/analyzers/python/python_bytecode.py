"""
Approximate reconstruction of Python source code from bytecode.

Strategy:
  - Walks a `types.CodeType` and emulates a minimal (read-only) stack to
    rebuild per-line expressions (co_lnotab/co_lines).
  - Does not execute, does not perform I/O, does not use eval/exec.
  - Covers common opcodes; unknown ones are reported as comments and do not
    stop the process (returns best effort).

This module is designed not to propagate exceptions to the caller:
every risky operation is wrapped in try/except and degrades cleanly.
"""

from __future__ import annotations

import dis
import types
from typing import Any, List, Optional, Set, Tuple


# ─── Stack and formatting helpers ────────────────────────────────────────────
def _safe_repr(value: Any, max_len: int = 200) -> str:
    """Safe, bounded repr() to avoid runaway output."""
    try:
        text = repr(value)
    except Exception:  # noqa: BLE001
        text = f"<unrepr {type(value).__name__}>"
    if len(text) > max_len:
        text = text[: max_len - 3] + "..."
    return text


class _FrameStack:
    """Minimal typed stack with underflow-safe operations."""

    def __init__(self, max_size: int = 4096) -> None:
        self._items: List[str] = []
        self._max_size = max(16, max_size)

    def push(self, value: str) -> None:
        if len(self._items) >= self._max_size:
            # Keeps the most recent portion to degrade without exhausting memory.
            del self._items[0]
        self._items.append(value)

    def pop(self) -> str:
        if not self._items:
            return "?"
        return self._items.pop()

    def peek(self) -> str:
        if not self._items:
            return "?"
        return self._items[-1]

    def popn(self, n: int) -> List[str]:
        if n <= 0:
            return []
        if n > len(self._items):
            taken = list(self._items)
            self._items.clear()
            taken.extend(["?"] * (n - len(taken)))
            return taken
        out = self._items[-n:]
        del self._items[-n:]
        return out

    def __len__(self) -> int:
        return len(self._items)

    def tail(self, n: int) -> List[str]:
        if n <= 0:
            return []
        return list(self._items[-n:])


# ─── Main recovery ───────────────────────────────────────────────────────────
class BytecodeRestorer:
    """
    Source code reconstruction from a code object.

    Usage:
        text = BytecodeRestorer(code_obj, source_name).recover()
    """

    INDENT = "    "
    MAX_DEPTH = 16  # maximum scope depth to avoid runaway.
    MAX_STACK_SIZE = 4096
    MAX_INSTRUCTIONS_PER_SCOPE = 10000
    MAX_EMITTED_LINES_PER_SCOPE = 5000
    MAX_UNKNOWN_OPCODES_PER_SCOPE = 500
    MAX_TOTAL_OUTPUT_CHARS = 200000

    def __init__(self, code_obj: types.CodeType, source_name: str) -> None:
        self.code_obj = code_obj
        self.source_name = source_name
        # Auxiliary stack of code objects seen in LOAD_CONST. Consumed in
        # MAKE_FUNCTION to recover the real function bodies.
        self._pending_codes: List[types.CodeType] = []
        # Set of already rendered code objects (anti-cycle).
        self._seen_codes: Set[int] = set()
        # Safety metrics used to rate the reliability of the output.
        self._unknown_opcodes = 0
        self._truncated_scopes = 0
        self._runtime_guard_events = 0

    # ── Public API ───────────────────────────────────────────────────────
    def recover(self) -> str:
        header = [
            f"# Recovered code (approximate) from: {self.source_name}",
            "# Heuristic reconstruction from bytecode (no external decompiler)",
            "",
        ]
        try:
            body = self._render_module(self.code_obj)
        except Exception as exc:  # noqa: BLE001
            self._runtime_guard_events += 1
            body = [
                "# Advanced reconstruction failed unexpectedly.",
                f"# Internal reason: {type(exc).__name__}: {exc}",
            ]

        summary = self._build_security_summary()
        text = "\n".join(header + summary + [""] + body) + "\n"
        return self._truncate_output(text)

    def _build_security_summary(self) -> List[str]:
        confidence = "high"
        if self._truncated_scopes > 0 or self._runtime_guard_events > 0:
            confidence = "low"
        elif self._unknown_opcodes > 0:
            confidence = "medium"

        return [
            f"# Estimated reliability: {confidence}",
            (
                "# Metrics: "
                f"unsupported_opcodes={self._unknown_opcodes}, "
                f"truncated_scopes={self._truncated_scopes}, "
                f"guard_events={self._runtime_guard_events}"
            ),
        ]

    def _truncate_output(self, text: str) -> str:
        if len(text) <= self.MAX_TOTAL_OUTPUT_CHARS:
            return text
        footer = "\n# output truncated by safety limit\n"
        return text[: self.MAX_TOTAL_OUTPUT_CHARS - len(footer)] + footer

    @staticmethod
    def _compact_text(text: str, max_len: int = 120) -> str:
        clean = text.replace("\n", " ").replace("\r", " ")
        if len(clean) <= max_len:
            return clean
        return clean[: max_len - 3] + "..."

    def _format_instruction_comment(
        self,
        inst: dis.Instruction,
        stack: _FrameStack,
        pseudo: Optional[str] = None,
    ) -> str:
        arg = inst.argrepr if getattr(inst, "argrepr", None) else (
            str(inst.arg) if inst.arg is not None else ""
        )
        op_txt = f"{inst.offset:04d}: {inst.opname}" + (f" {arg}" if arg else "")
        stack_tail = [self._compact_text(item, 48) for item in stack.tail(4)]
        stack_txt = ", ".join(stack_tail) if stack_tail else "-"
        if pseudo:
            pseudo_txt = self._compact_text(pseudo, 160)
            return f"{pseudo_txt}  |  bytecode={op_txt}  |  stack=[{stack_txt}]"
        return f"bytecode={op_txt}  |  stack=[{stack_txt}]"

    # ── Render per scope ─────────────────────────────────────────────────
    def _render_module(self, code: types.CodeType) -> List[str]:
        return self._render_code(code, indent_level=0, is_module=True)

    def _render_function(
        self,
        code: types.CodeType,
        fn_name: str,
        indent_level: int,
    ) -> List[str]:
        signature = self._build_signature(code)
        header = f"{self.INDENT * indent_level}def {fn_name}({signature}):"
        body = self._render_code(code, indent_level + 1, is_module=False)
        if not body:
            body = [f"{self.INDENT * (indent_level + 1)}pass"]
        return [header] + body

    def _render_class(
        self,
        code: types.CodeType,
        cls_name: str,
        indent_level: int,
    ) -> List[str]:
        header = f"{self.INDENT * indent_level}class {cls_name}:"
        body = self._render_code(code, indent_level + 1, is_module=False)
        if not body:
            body = [f"{self.INDENT * (indent_level + 1)}pass"]
        return [header] + body

    # ── Core: generic render with mini-stack ─────────────────────────────
    def _render_code(
        self,
        code: types.CodeType,
        indent_level: int,
        is_module: bool,
    ) -> List[str]:
        # Anti-runaway guards: maximum depth and cycles.
        if indent_level > self.MAX_DEPTH:
            return [f"{self.INDENT * indent_level}# scope skipped (maximum depth)"]
        code_id = id(code)
        if code_id in self._seen_codes:
            return [f"{self.INDENT * indent_level}# scope already rendered (cyclic)"]
        self._seen_codes.add(code_id)

        # Isolates the stack of code objects pending for this scope.
        saved_codes_len = len(self._pending_codes)

        try:
            instructions = dis.get_instructions(code)
        except Exception:  # noqa: BLE001
            self._runtime_guard_events += 1
            del self._pending_codes[saved_codes_len:]
            return [f"{self.INDENT * indent_level}# bytecode unreadable for dis"]

        lines_out: List[str] = []
        stack = _FrameStack(max_size=self.MAX_STACK_SIZE)
        pad = self.INDENT * indent_level

        # Temporary buffers to build calls with kwargs
        kw_names: Optional[Tuple[str, ...]] = None
        unknown_in_scope = 0

        for idx, inst in enumerate(instructions):
            if idx >= self.MAX_INSTRUCTIONS_PER_SCOPE:
                lines_out.append(
                    f"{pad}# scope truncated: instruction limit reached"
                )
                self._truncated_scopes += 1
                break
            try:
                unknown_before = self._unknown_opcodes
                kw_names = self._dispatch_opcode(
                    inst=inst,
                    stack=stack,
                    lines_out=lines_out,
                    indent=pad,
                    indent_level=indent_level,
                    kw_names=kw_names,
                )
            except Exception as exc:  # noqa: BLE001
                self._runtime_guard_events += 1
                lines_out.append(
                    f"{pad}# unhandled opcode ({type(exc).__name__}) -> "
                    f"{self._format_instruction_comment(inst, stack)}"
                )
                unknown_before = self._unknown_opcodes

            if self._unknown_opcodes > unknown_before:
                unknown_in_scope += self._unknown_opcodes - unknown_before
                if unknown_in_scope >= self.MAX_UNKNOWN_OPCODES_PER_SCOPE:
                    lines_out.append(
                        f"{pad}# scope truncated: too many unsupported opcodes"
                    )
                    self._truncated_scopes += 1
                    break

            if len(lines_out) >= self.MAX_EMITTED_LINES_PER_SCOPE:
                lines_out.append(
                    f"{pad}# scope truncated: rebuilt-line limit reached"
                )
                self._truncated_scopes += 1
                break

        # Closes the pending stack expression as an informative comment
        if len(stack) > 0:
            top = stack.peek()
            if top and top != "?" and not is_module:
                lines_out.append(f"{pad}# pending stack: {top}")

        # Restores the auxiliary stack so sibling scopes are not polluted.
        del self._pending_codes[saved_codes_len:]

        # Deduplicates identical consecutive comments to reduce noise.
        return self._dedupe_consecutive(lines_out)

    @staticmethod
    def _dedupe_consecutive(lines: List[str]) -> List[str]:
        """Collapses identical consecutive comment lines."""
        out: List[str] = []
        last: Optional[str] = None
        repeat = 0
        for line in lines:
            if line == last and line.lstrip().startswith("#"):
                repeat += 1
                continue
            if last is not None:
                out.append(f"{last}  # x{repeat + 1}" if repeat > 0 else last)
            last = line
            repeat = 0
        if last is not None:
            out.append(f"{last}  # x{repeat + 1}" if repeat > 0 else last)
        return out

    # ── Per-opcode dispatch ──────────────────────────────────────────────
    def _dispatch_opcode(
        self,
        inst: dis.Instruction,
        stack: _FrameStack,
        lines_out: List[str],
        indent: str,
        indent_level: int,
        kw_names: Optional[Tuple[str, ...]],
    ) -> Optional[Tuple[str, ...]]:
        op = inst.opname

        # ── Operand loading ──
        if op == "LOAD_CONST":
            if isinstance(inst.argval, types.CodeType):
                self._pending_codes.append(inst.argval)
                stack.push(f"<code:{inst.argval.co_name}>")
            else:
                stack.push(_safe_repr(inst.argval))
            return kw_names

        if op in {"LOAD_NAME", "LOAD_FAST", "LOAD_DEREF"}:
            name = inst.argval if isinstance(inst.argval, str) else str(inst.argval)
            stack.push(name)
            return kw_names

        if op == "LOAD_GLOBAL":
            name = inst.argval if isinstance(inst.argval, str) else str(inst.argval)
            # Python 3.11+: the low bit of arg means push_null before the name,
            # so CALL can consume that entry as "no self".
            if isinstance(inst.arg, int) and (inst.arg & 1):
                stack.push("NULL")
            stack.push(name)
            return kw_names

        if op == "LOAD_ATTR":
            base = stack.pop()
            stack.push(f"{base}.{inst.argval}")
            # Python 3.12: if the low bit of arg is set, this is method style
            # and CPython also pushes a placeholder ("self" or NULL). We emulate
            # it so CALL can consume that second entry without desynchronizing.
            if isinstance(inst.arg, int) and (inst.arg & 1):
                # Reorder so the top entry is still the callable.
                top = stack.pop()
                stack.push("NULL")
                stack.push(top)
            return kw_names

        if op == "LOAD_METHOD":
            base = stack.pop()
            stack.push(f"{base}.{inst.argval}")
            return kw_names

        if op == "LOAD_BUILD_CLASS":
            stack.push("__build_class__")
            return kw_names

        # ── Storage ──
        if op in {"STORE_NAME", "STORE_FAST", "STORE_GLOBAL", "STORE_DEREF"}:
            value = stack.pop()
            target = inst.argval
            # Suppresses redundant assignments after an already emitted def/class.
            if value.startswith("<func ") or value.startswith("<class "):
                return kw_names
            if value.startswith("<code:"):
                # Code object without MAKE_FUNCTION (uncommon): skip the noisy assignment.
                return kw_names
            # Suppresses X = X (typical artifact after IMPORT_FROM/IMPORT_NAME).
            if value == target:
                return kw_names
            lines_out.append(f"{indent}{target} = {value}")
            return kw_names

        if op == "STORE_ATTR":
            value = stack.pop()
            obj = stack.pop()
            lines_out.append(f"{indent}{obj}.{inst.argval} = {value}")
            return kw_names

        if op == "STORE_SUBSCR":
            index = stack.pop()
            container = stack.pop()
            value = stack.pop()
            lines_out.append(f"{indent}{container}[{index}] = {value}")
            return kw_names

        # ── Returns ──
        if op == "RETURN_VALUE":
            value = stack.pop()
            if indent_level == 0 and value in {"None", "'None'"}:
                return kw_names
            lines_out.append(f"{indent}return {value}")
            return kw_names

        if op == "RETURN_CONST":  # Python 3.12+
            value = _safe_repr(inst.argval)
            if indent_level == 0 and value == "None":
                return kw_names
            lines_out.append(f"{indent}return {value}")
            return kw_names

        # ── Pop ──
        if op == "POP_TOP":
            expr = stack.pop()
            if expr and expr != "?":
                # Kept as an expression statement so calls are not lost.
                lines_out.append(f"{indent}{expr}")
            return kw_names

        # ── Calls ──
        if op == "KW_NAMES":
            names = inst.argval
            if isinstance(names, tuple):
                return tuple(str(n) for n in names)
            return kw_names

        if op in {"CALL", "CALL_FUNCTION", "CALL_METHOD"}:
            argc = inst.arg if isinstance(inst.arg, int) else 0
            args = stack.popn(argc)
            callable_repr = stack.pop()
            # In CALL (3.11+) there may be a NULL placeholder below the callable
            # (for plain functions) or a real "self" (for methods via LOAD_ATTR).
            # It is only consumed if it is literally "NULL"; self is already
            # embedded in `callable_repr` through LOAD_ATTR/LOAD_METHOD.
            if len(stack) > 0 and stack.peek() == "NULL":
                stack.pop()
            # If the callable was lost, try to rescue a valid name below.
            if callable_repr in {"?", "NULL"}:
                backup = stack.pop() if len(stack) > 0 else None
                if backup and backup not in {"?", "NULL", "None"}:
                    callable_repr = backup

            if kw_names:
                kw_count = len(kw_names)
                positional = args[: argc - kw_count]
                kw_values = args[argc - kw_count :]
                rendered = list(positional)
                for name, value in zip(kw_names, kw_values):
                    rendered.append(f"{name}={value}")
                args_str = ", ".join(rendered)
            else:
                args_str = ", ".join(args)

            stack.push(f"{callable_repr}({args_str})")
            return None  # consume kw_names

        if op == "CALL_FUNCTION_KW":
            argc = inst.arg if isinstance(inst.arg, int) else 0
            kw_tuple_raw = stack.pop()
            args = stack.popn(argc)
            callable_repr = stack.pop()
            stack.push(f"{callable_repr}(*{_safe_repr(args)}, **{kw_tuple_raw})")
            return kw_names

        if op == "CALL_FUNCTION_EX":
            kwargs_repr = ""
            if inst.arg and inst.arg & 0x01:
                kwargs_repr = stack.pop()
            args_repr = stack.pop()
            callable_repr = stack.pop()
            if kwargs_repr:
                stack.push(f"{callable_repr}(*{args_repr}, **{kwargs_repr})")
            else:
                stack.push(f"{callable_repr}(*{args_repr})")
            return kw_names

        # ── Nested functions and classes ──
        if op == "MAKE_FUNCTION":
            inner_code: Optional[types.CodeType] = None
            # In Python 3.11+ MAKE_FUNCTION only consumes the code object.
            # In earlier versions there may be a qualname on top.
            top = stack.pop()
            if top.startswith("<code:"):
                inner_code = self._pending_codes.pop() if self._pending_codes else None
            else:
                # top could be the qualname; try the next one as the code object.
                maybe_code = stack.pop() if len(stack) > 0 else "?"
                if maybe_code.startswith("<code:") and self._pending_codes:
                    inner_code = self._pending_codes.pop()
            fn_name = (
                inner_code.co_name if isinstance(inner_code, types.CodeType) else "func"
            )
            if isinstance(inner_code, types.CodeType):
                rendered = self._render_function(inner_code, fn_name, indent_level)
                lines_out.extend(rendered)
                lines_out.append("")
            else:
                lines_out.append(f"{indent}def {fn_name}(...):  # body not recoverable")
                lines_out.append(f"{indent}{self.INDENT}pass")
            stack.push(f"<func {fn_name}>")
            return kw_names

        # ── Imports ──
        if op == "IMPORT_NAME":
            _level = stack.pop()
            _fromlist = stack.pop()
            module_name = inst.argval
            lines_out.append(f"{indent}import {module_name}")
            stack.push(module_name)
            return kw_names

        if op == "IMPORT_FROM":
            base = stack.peek()
            lines_out.append(f"{indent}from {base} import {inst.argval}")
            stack.push(inst.argval)
            return kw_names

        # ── Container construction ──
        if op == "BUILD_LIST":
            items = stack.popn(inst.arg or 0)
            stack.push("[" + ", ".join(items) + "]")
            return kw_names

        if op == "BUILD_TUPLE":
            items = stack.popn(inst.arg or 0)
            stack.push("(" + ", ".join(items) + ")")
            return kw_names

        if op == "BUILD_SET":
            items = stack.popn(inst.arg or 0)
            stack.push("{" + ", ".join(items) + "}")
            return kw_names

        if op == "BUILD_MAP":
            count = (inst.arg or 0) * 2
            items = stack.popn(count)
            pairs = []
            for k, v in zip(items[0::2], items[1::2]):
                pairs.append(f"{k}: {v}")
            stack.push("{" + ", ".join(pairs) + "}")
            return kw_names

        if op == "BUILD_CONST_KEY_MAP":
            keys = stack.pop()
            values = stack.popn(inst.arg or 0)
            stack.push(f"dict(zip({keys}, {values}))")
            return kw_names

        if op == "LIST_EXTEND":
            extra = stack.pop()
            base = stack.pop()
            # extra is usually a const tuple "(1, 2, 3)"; render it as a list.
            if extra.startswith("(") and extra.endswith(")"):
                inner = extra[1:-1]
                stack.push(f"[{inner}]" if base in {"[]", "[ ]"} else f"{base} + [{inner}]")
            else:
                stack.push(f"{base} + list({extra})")
            return kw_names

        if op == "SET_UPDATE":
            extra = stack.pop()
            base = stack.pop()
            stack.push(f"{base} | set({extra})")
            return kw_names

        if op in {"DICT_UPDATE", "DICT_MERGE"}:
            extra = stack.pop()
            base = stack.pop()
            stack.push(f"{{**{base}, **{extra}}}")
            return kw_names

        if op == "LIST_TO_TUPLE":
            value = stack.pop()
            if value.startswith("[") and value.endswith("]"):
                stack.push("(" + value[1:-1] + ")")
            else:
                stack.push(f"tuple({value})")
            return kw_names

        # ── Binary and unary (simplified) ──
        if op in {"BINARY_ADD", "BINARY_SUBTRACT", "BINARY_MULTIPLY",
                  "BINARY_TRUE_DIVIDE", "BINARY_FLOOR_DIVIDE", "BINARY_MODULO",
                  "BINARY_POWER", "BINARY_AND", "BINARY_OR", "BINARY_XOR",
                  "BINARY_LSHIFT", "BINARY_RSHIFT"}:
            sym = {
                "BINARY_ADD": "+", "BINARY_SUBTRACT": "-", "BINARY_MULTIPLY": "*",
                "BINARY_TRUE_DIVIDE": "/", "BINARY_FLOOR_DIVIDE": "//",
                "BINARY_MODULO": "%", "BINARY_POWER": "**",
                "BINARY_AND": "&", "BINARY_OR": "|", "BINARY_XOR": "^",
                "BINARY_LSHIFT": "<<", "BINARY_RSHIFT": ">>",
            }[op]
            right = stack.pop()
            left = stack.pop()
            stack.push(f"({left} {sym} {right})")
            return kw_names

        if op == "BINARY_OP":  # Python 3.11+
            right = stack.pop()
            left = stack.pop()
            sym = inst.argrepr if getattr(inst, "argrepr", None) else "<op>"
            stack.push(f"({left} {sym} {right})")
            return kw_names

        if op == "BINARY_SUBSCR":
            index = stack.pop()
            container = stack.pop()
            stack.push(f"{container}[{index}]")
            return kw_names

        if op == "COMPARE_OP":
            right = stack.pop()
            left = stack.pop()
            stack.push(f"({left} {inst.argval} {right})")
            return kw_names

        if op == "IS_OP":
            right = stack.pop()
            left = stack.pop()
            stack.push(f"({left} is{' not' if inst.arg else ''} {right})")
            return kw_names

        if op == "CONTAINS_OP":
            right = stack.pop()
            left = stack.pop()
            stack.push(f"({left}{' not' if inst.arg else ''} in {right})")
            return kw_names

        if op == "UNARY_NEGATIVE":
            stack.push(f"(-{stack.pop()})")
            return kw_names

        if op == "UNARY_NOT":
            stack.push(f"(not {stack.pop()})")
            return kw_names

        if op == "UNARY_INVERT":
            stack.push(f"(~{stack.pop()})")
            return kw_names

        # ── Control-flow operations: informational markers only ──
        if op in {"POP_JUMP_FORWARD_IF_FALSE", "POP_JUMP_FORWARD_IF_TRUE",
                  "POP_JUMP_BACKWARD_IF_FALSE", "POP_JUMP_BACKWARD_IF_TRUE",
                  "POP_JUMP_IF_FALSE", "POP_JUMP_IF_TRUE",
                  "JUMP_FORWARD", "JUMP_BACKWARD", "JUMP_ABSOLUTE"}:
            # Exact flow is not rebuilt, but a minimal hint is left.
            if op.startswith("POP_JUMP") and len(stack) > 0:
                cond = stack.pop()
                lines_out.append(
                    f"{indent}# "
                    f"{self._format_instruction_comment(inst, stack, pseudo=f'if {cond}: ...') }"
                )
            else:
                lines_out.append(
                    f"{indent}# "
                    f"{self._format_instruction_comment(inst, stack, pseudo='flow not rebuilt') }"
                )
            return kw_names

        # ── Trivial ignorable operations ──
        if op in {"RESUME", "NOP", "CACHE", "PRECALL",
                  "MAKE_CELL", "COPY_FREE_VARS", "RETURN_GENERATOR"}:
            return kw_names

        if op == "PUSH_NULL":
            stack.push("NULL")
            return kw_names

        if op == "COPY":
            # COPY <n>: duplicates the entry at position n from the top (1-based).
            n = inst.arg or 1
            if len(stack) >= n:
                stack.push(stack._items[-n])  # noqa: SLF001
            else:
                stack.push("?")
            return kw_names

        if op == "SWAP":
            # SWAP <n>: swaps the top with position n (n>=2).
            n = inst.arg or 2
            if len(stack) >= n and n >= 2:
                items = stack._items  # noqa: SLF001
                items[-1], items[-n] = items[-n], items[-1]
            return kw_names

        # ── f-strings (FORMAT_VALUE / BUILD_STRING) ──
        if op == "FORMAT_VALUE":
            flags = inst.arg or 0
            spec = ""
            if flags & 0x04:
                spec = stack.pop()
            value = stack.pop()
            # Strip quotes from literal strings
            if spec.startswith("'") and spec.endswith("'"):
                spec = spec[1:-1]
            inner = value
            if inner.startswith("'") and inner.endswith("'"):
                inner = inner[1:-1]
            if spec:
                stack.push(f"f'{{{inner}:{spec}}}'")
            else:
                stack.push(f"f'{{{inner}}}'")
            return kw_names

        if op == "BUILD_STRING":
            parts = stack.popn(inst.arg or 0)
            stack.push("(" + " + ".join(parts) + ")" if parts else "''")
            return kw_names

        # ── UNPACK_SEQUENCE: a, b = expr ──
        if op == "UNPACK_SEQUENCE":
            source = stack.pop()
            count = inst.arg or 0
            # Emit placeholders that the following STORE_* will consume.
            # Pushed in reverse order because STORE_* consumes from the top.
            for i in range(count - 1, -1, -1):
                stack.push(f"{source}[{i}]")
            return kw_names

        if op == "UNPACK_EX":
            source = stack.pop()
            # Simplified version: the exact pattern is not rebuilt.
            count = ((inst.arg or 0) & 0xFF) + (((inst.arg or 0) >> 8) & 0xFF) + 1
            for i in range(count):
                stack.push(f"{source}[?]")
            return kw_names

        # ── Default: log as a comment and continue ──
        self._unknown_opcodes += 1
        lines_out.append(
            f"{indent}# unsupported opcode -> "
            f"{self._format_instruction_comment(inst, stack)}"
        )
        return kw_names

    # ── Support ─────────────────────────────────────────────────────────
    def _find_nested_code(self, qualified_name: str) -> Optional[types.CodeType]:
        """Looks up a code object by name inside co_consts."""
        target = qualified_name.split(".")[-1]
        for const in self.code_obj.co_consts:
            if isinstance(const, types.CodeType) and const.co_name == target:
                return const

        # Recursive search one extra level deep (common closures).
        for const in self.code_obj.co_consts:
            if isinstance(const, types.CodeType):
                for inner in const.co_consts:
                    if isinstance(inner, types.CodeType) and inner.co_name == target:
                        return inner
        return None

    @staticmethod
    def _build_signature(code: types.CodeType) -> str:
        # Positional args + kwonly
        argcount = code.co_argcount
        kwonly = code.co_kwonlyargcount
        total = argcount + kwonly
        names = list(code.co_varnames[:total])
        flags = code.co_flags
        extras: List[str] = []
        idx = total
        if flags & 0x04:  # CO_VARARGS
            if idx < len(code.co_varnames):
                extras.append(f"*{code.co_varnames[idx]}")
                idx += 1
            else:
                extras.append("*args")
        if flags & 0x08:  # CO_VARKEYWORDS
            if idx < len(code.co_varnames):
                extras.append(f"**{code.co_varnames[idx]}")
            else:
                extras.append("**kwargs")
        # kwonly separator marker if present
        result: List[str] = list(names[:argcount])
        if kwonly:
            if not (flags & 0x04):
                result.append("*")
            result.extend(names[argcount : argcount + kwonly])
        # Inserts *args/**kwargs at the correct position
        if extras:
            result = list(names[:argcount]) + extras + (
                names[argcount : argcount + kwonly] if kwonly else []
            )
        return ", ".join(result)


def recover_source(code_obj: types.CodeType, source_name: str) -> str:
    """Convenience entry point for external use."""
    return BytecodeRestorer(code_obj, source_name).recover()
