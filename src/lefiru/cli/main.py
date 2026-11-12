"""Command-line interface for lefiru."""

import argparse
import logging
import sys
from pathlib import Path

from lefiru.core.analyzers.excel.com_runtime import ComNotAvailableError
from lefiru.core.catalog import EXCEL_EXTENSIONS, PYTHON_EXTENSIONS
from lefiru.core.orchestrator import AnalysisOrchestrator
from lefiru.core.analysis_support import prepare_output_directories, setup_logging
from lefiru.paths import ensure_output_root
from lefiru.reporting.report_writer import AnalysisReportWriter


def main():
    """CLI main function"""
    parser = argparse.ArgumentParser(
        prog="lefiru",
        description=(
            "LeFiru Security Analyzer - security analysis for Excel and Python\n"
            "\n"
            "How to open the graphical interface:\n"
            "  lefiru-analyzer\n"
            "\n"
            "Command-line analysis: use --path and --analysis (see examples below)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
            Usage examples:
            lefiru-analyzer                                  (open the graphical interface)
            lefiru --path "workbook.xlsm" --analysis static
            lefiru --path "workbook.xlsx" --analysis com --output results
            lefiru --path "template.xltm" --analysis static
            lefiru --path "script.py" --output results
            lefiru --path "app.exe" --output results
                    """
    )
    
    parser.add_argument(
        "--path",
        "-P",
        required=True,
        help="Path to the file to assess (.xlsx, .xlsm, .xlsb, .xltx, .xltm, .xlam, .py, .pyc, .exe)"
    )
    
    
    parser.add_argument(
        "--analysis",
        "-a",
        choices=["static", "com", "both"],
        default="both",
        help="Analysis mode: static, com or both (default)"
    )

    
    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help=(
            "Output directory for reports "
            "(default: folder resolved by lefiru.paths.output_root())"
        )
    )
    
    parser.add_argument(
        "--debug",
        "-d",
        action="store_true",
        help="Debug mode (writes the detailed log file and shows DEBUG messages)"
    )

    
    parser.add_argument(
    "--tests",
    "-t",
    help=(
        "Tests to run (comma separated). "
        "Excel: protections,vba,patterns,connections,formulas,password. "
        "Python: python_dynamic_execution,python_dangerous_commands,"
        "python_deserialization,python_credentials,python_connections,python_traceability "
        "(or python_analysis as the full alias). "
        "Default: ALL"
    ),
    default="ALL"
   )
    
    args = parser.parse_args()
    
    
    if args.tests == "ALL":
        tests = ["ALL"]
    else:
        tests = [p.strip() for p in args.tests.split(",")]

    excel_file = Path(args.path)
    suffix = excel_file.suffix.lower()

    if suffix not in EXCEL_EXTENSIONS | PYTHON_EXTENSIONS:
        sys.stderr.write(
            f"Error: unsupported extension '{suffix or 'no extension'}'. "
            "Accepted formats: "
            f"{', '.join(sorted(EXCEL_EXTENSIONS | PYTHON_EXTENSIONS))}\n"
        )
        sys.exit(99)

    type_output = "python" if suffix in PYTHON_EXTENSIONS else "excel"
    output_root = Path(args.output).expanduser() if args.output else ensure_output_root()
    base_output = output_root / type_output

    output_paths = prepare_output_directories(
    base_output=str(base_output),
    excel_file=excel_file
    )

    
    # Configure logging: the log file is only generated in debug mode
    log_level = logging.DEBUG if args.debug else logging.INFO
    log_file = setup_logging(
        output_paths["root"],
        log_level,
        enable_file=args.debug,
    )
    logger = logging.getLogger(__name__)
    
    
    try:
        # Create the checker instance
       
        checker = AnalysisOrchestrator(
            file_path=args.path,
            mode=args.analysis,
            tests=tests,          
            output_dir=str(output_paths["root"]),
        )

        
        # Run the analysis
        results = checker.run_full_analysis()

        
        # Generate reports
        logger.info("\n" + "=" * 80)
        logger.info("GENERATING REPORTS")
        logger.info("=" * 80)
        
        report_gen = AnalysisReportWriter(output_paths["root"])
        json_file, report_file = report_gen.generate_reports(results)
        
        logger.info(f"\nJSON report: {json_file}")
        if report_file:
            logger.info(f"PDF report: {report_file}")
        if log_file:
            logger.info(f"Detailed log: {log_file}")
        
       
        
        # Final summary
        status = results["compliance"]["general_status"]
        logger.info("\n" + "=" * 80)
        logger.info(f"ANALYSIS COMPLETED: {status}")
        logger.info("=" * 80)
        
        # Exit code based on compliance
        if status == "VULNERABLE":
            sys.exit(1)
        elif status == "COMPLIANT_WITH_OBSERVATIONS":
            sys.exit(2)
        else:
            sys.exit(0)
            
    except ComNotAvailableError as e:
        # Environment condition: explains what is missing without dumping a traceback.
        logger.error(f"\nCOM MODE NOT AVAILABLE: {e}")
        sys.exit(99)

    except Exception as e:
        logger.error(f"\nFATAL ERROR: {str(e)}", exc_info=True)
        sys.exit(99)


if __name__ == "__main__":
    main()
