import os
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from .utils.logging import get_logger
from .utils.url import normalize_base
from .http_client import HttpClient
from .crawler import Crawler
from .analysis.headers import analyze_security_headers
from .analysis.cookies import analyze_cookies
from .analysis.forms import extract_form_findings
from .analysis.xss import test_reflected_xss
from .analysis.sql_injection import test_basic_sqli
from .analysis.fingerprint import fingerprint_stack
from .analysis.discovery import check_directory_listing, probe_hidden_paths, probe_exposed_files
from .reporting.report_builder import ReportBuilder, finding_dict

dataclass
class Config:
    target: str
    max_pages: int
    depth: int
    timeout: int
    user_agent: str
    output_dir: str
    formats: list
    ignore_robots: bool
    delay: float
    threads: int
    verbose: bool
    json_output: bool

dataclass
class ScanState:
    pages: dict = field(default_factory=dict)  # url -> {status, content, headers}
    forms: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    stack: dict = field(default_factory=dict)
    start_time: str = ""
    end_time: str = ""
    config_used: dict = field(default_factory=dict)
    directory_listing: list = field(default_factory=list)
    probed_hidden_paths: list = field(default_factory=list)
    exposed_files: list = field(default_factory=list)

def severity_sort_key(f):
    mapping = {"High": 3, "Medium": 2, "Low": 1, "Info": 0}
    return mapping.get(f.get("severity","Info"), 0)

def run_scan(args):
    logger = get_logger(args.verbose)
    target = normalize_base(args.target)
    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    cfg = Config(
        target=target,
        max_pages=args.max_pages,
        depth=args.depth,
        timeout=args.timeout,
        user_agent=args.user_agent,
        output_dir=args.output_dir,
        formats=formats,
        ignore_robots=args.ignore_robots,
        delay=args.delay,
        threads=args.threads,
        verbose=args.verbose,
        json_output=args.json or ("json" in formats)
    )
    state = ScanState()
    state.start_time = datetime.now(timezone.utc).isoformat()
    state.config_used = cfg.__dict__.copy()

    os.makedirs(cfg.output_dir, exist_ok=True)
    logger.info(f"Starting scan of {cfg.target}")

    client = HttpClient(
        timeout=cfg.timeout,
        user_agent=cfg.user_agent,
        delay=cfg.delay,
        logger=logger
    )

    crawler = Crawler(
        client=client,
        base_url=cfg.target,
        max_pages=cfg.max_pages,
        max_depth=cfg.depth,
        logger=logger,
        obey_robots=not cfg.ignore_robots
    )

    # Crawl
    crawler.crawl()
    state.pages = crawler.pages
    state.forms = crawler.forms

    # Directory listing detection + hidden paths + exposed files
    for url, meta in state.pages.items():
        if meta.get("content"):
            dl = check_directory_listing(url, meta.get("content"))
            if dl:
                state.directory_listing.append(dl)
    state.probed_hidden_paths = probe_hidden_paths(client, cfg.target, crawler.hidden_wordlist)
    state.exposed_files = probe_exposed_files(client, cfg.target, crawler.exposed_files_list)

    # Security headers
    if state.pages:
        root_meta = state.pages.get(cfg.target) or next(iter(state.pages.values()))
        headers = root_meta.get("headers", {})
        header_findings = analyze_security_headers(headers, cfg.target)
        state.findings.extend(header_findings)

    # Cookie issues
    for url, meta in state.pages.items():
        cookie_findings = analyze_cookies(meta.get("cookies", []), url)
        state.findings.extend(cookie_findings)

    # Forms-based + parameter reflection
    form_findings = extract_form_findings(state.forms)
    state.findings.extend(form_findings)

    # Reflection tests (XSS-like)
    xss_findings = test_reflected_xss(client, state.pages, state.forms)
    state.findings.extend(xss_findings)

    # Basic SQLi probes
    sqli_findings = test_basic_sqli(client, state.pages, state.forms)
    state.findings.extend(sqli_findings)

    # Fingerprint
    state.stack = fingerprint_stack(state.pages)

    # Directory listing as findings
    for entry in state.directory_listing:
        state.findings.append(finding_dict(
            title="Potential Directory Listing Enabled",
            category="Discovery",
            severity="Low",
            location=entry["url"],
            description="Page appears to expose a raw directory listing.",
            evidence="...Index of /... observed",
            recommendation="Disable autoindex/directory listing for production resources."
        ))

    for hp in state.probed_hidden_paths:
        if hp["status"] and hp["status"] < 400:
            state.findings.append(finding_dict(
                title="Accessible Hidden Path",
                category="Discovery",
                severity="Info",
                location=hp["url"],
                description="Hidden path from small wordlist is accessible.",
                evidence=f"Status {hp['status']}",
                recommendation="Review and restrict or remove unused paths."
            ))

    for ef in state.exposed_files:
        if ef["status"] and ef["status"] == 200:
            state.findings.append(finding_dict(
                title="Potentially Sensitive Exposed File",
                category="Discovery",
                severity="Medium",
                location=ef["url"],
                description="A known sensitive filename responded with 200 OK.",
                evidence=f"Status 200 for {ef['path']}",
                recommendation="Remove or restrict sensitive files from public access."
            ))

    # Sort findings by severity then title
    state.findings.sort(key=severity_sort_key, reverse=True)

    state.end_time = datetime.now(timezone.utc).isoformat()

    # Build report
    builder = ReportBuilder(
        target=cfg.target,
        state=state,
        output_dir=cfg.output_dir,
        output_formats=cfg.formats,
        json_output=cfg.json_output,
        logger=logger
    )
    output_files = builder.generate()

    logger.info("Scan complete. Outputs:")
    for f in output_files:
        logger.info(f"  {f}")
