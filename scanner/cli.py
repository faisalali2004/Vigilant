import argparse
from .main import run_scan

def build_parser():
    parser = argparse.ArgumentParser(
        prog="lightscan",
        description="Lightweight Non-Intrusive Web Vulnerability Scanner (Educational Use Only)"
    )
    parser.add_argument("target", help="Base target URL, e.g. https://example.com")
    parser.add_argument("--max-pages", type=int, default=100, help="Maximum pages to crawl (default 100)")
    parser.add_argument("--depth", type=int, default=3, help="Maximum crawl depth (default 3)")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout seconds (default 10)")
    parser.add_argument("--user-agent", default="LightScan/1.0", help="Custom User-Agent")
    parser.add_argument("--output-dir", default="reports", help="Directory to write reports")
    parser.add_argument("--format", default="md,html,txt", help="Comma-separated output formats: md,html,txt,json")
    parser.add_argument("--ignore-robots", action="store_true", default=False, help="Ignore robots.txt directives")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay (seconds) between requests (default 0)")
    parser.add_argument("--threads", type=int, default=1, help="(Future) number of threads (currently single-threaded)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug logging")
    parser.add_argument("--json", action="store_true", help="Also export JSON output")
    return parser

def main():
    parser = build_parser()
    args = parser.parse_args()
    run_scan(args)

if __name__ == "__main__":
    main()
