#!/usr/bin/env python3
"""
Isnad CLI

Command-line interface for scanning agent skills.

Usage:
    python cli.py scan <url_or_file>
    python cli.py scan --content "skill content..."
"""

import argparse
import json
import sys
import urllib.request
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from scanner.core import scan_skill, RiskLevel


# ANSI colors
class Colors:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"


def colorize_risk(risk: str) -> str:
    """Add color to risk level."""
    colors = {
        "clean": Colors.GREEN,
        "low": Colors.CYAN,
        "medium": Colors.YELLOW,
        "high": Colors.RED,
        "critical": Colors.MAGENTA + Colors.BOLD,
    }
    color = colors.get(risk.lower(), "")
    return f"{color}{risk.upper()}{Colors.RESET}"


def colorize_severity(severity: str) -> str:
    """Add color to severity."""
    colors = {
        "info": Colors.BLUE,
        "low": Colors.CYAN,
        "medium": Colors.YELLOW,
        "high": Colors.RED,
        "critical": Colors.MAGENTA + Colors.BOLD,
    }
    color = colors.get(severity.lower(), "")
    return f"{color}{severity.upper()}{Colors.RESET}"


def print_result(result: dict, json_output: bool = False):
    """Print scan result to console."""
    if json_output:
        print(json.dumps(result, indent=2))
        return
    
    print()
    print(f"{Colors.BOLD}═══════════════════════════════════════════════════════{Colors.RESET}")
    print(f"{Colors.BOLD}  ISNAD SCAN RESULTS{Colors.RESET}")
    print(f"{Colors.BOLD}═══════════════════════════════════════════════════════{Colors.RESET}")
    print()
    
    # Risk level
    print(f"  {Colors.BOLD}Risk Level:{Colors.RESET} {colorize_risk(result['risk_level'])}")
    print(f"  {Colors.BOLD}Content Hash:{Colors.RESET} {result['content_hash'][:16]}...")
    
    if result.get('skill_url'):
        print(f"  {Colors.BOLD}URL:{Colors.RESET} {result['skill_url']}")
    
    print()
    
    # Findings
    findings = result.get('findings', [])
    if findings:
        print(f"{Colors.BOLD}  FINDINGS ({len(findings)}){Colors.RESET}")
        print(f"  {'─' * 50}")
        
        for i, finding in enumerate(findings, 1):
            severity = colorize_severity(finding['severity'])
            category = finding['category'].replace('_', ' ').title()
            
            print(f"\n  [{i}] {severity} — {category}")
            print(f"      {finding['description']}")
            
            if finding.get('location'):
                print(f"      {Colors.CYAN}📍 {finding['location']}{Colors.RESET}")
            
            if finding.get('recommendation'):
                print(f"      {Colors.YELLOW}💡 {finding['recommendation']}{Colors.RESET}")
    else:
        print(f"  {Colors.GREEN}✅ No security issues detected{Colors.RESET}")
    
    print()
    
    # Permissions
    permissions = result.get('permissions_inferred', {})
    has_permissions = any(v for v in permissions.values())
    
    if has_permissions:
        print(f"{Colors.BOLD}  INFERRED PERMISSIONS{Colors.RESET}")
        print(f"  {'─' * 50}")
        
        for perm_type, items in permissions.items():
            if items:
                print(f"\n  {Colors.BOLD}{perm_type}:{Colors.RESET}")
                for item in items[:10]:  # Limit display
                    print(f"    • {item}")
                if len(items) > 10:
                    print(f"    ... and {len(items) - 10} more")
    
    # URLs found
    urls = result.get('urls_found', [])
    if urls:
        print()
        print(f"{Colors.BOLD}  URLS FOUND ({len(urls)}){Colors.RESET}")
        print(f"  {'─' * 50}")
        for url in urls[:10]:
            print(f"    • {url}")
        if len(urls) > 10:
            print(f"    ... and {len(urls) - 10} more")
    
    print()
    print(f"{Colors.BOLD}═══════════════════════════════════════════════════════{Colors.RESET}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Isnad - Security scanner for agent skills",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan https://example.com/skill.md
  %(prog)s scan ./my-skill.md
  %(prog)s scan --content "import os; os.environ['KEY']"
  %(prog)s scan skill.md --json
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan a skill for security issues')
    scan_parser.add_argument('target', nargs='?', help='URL or file path to scan')
    scan_parser.add_argument('--content', '-c', help='Raw content to scan')
    scan_parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == 'scan':
        content = None
        url = None
        
        if args.content:
            content = args.content
        elif args.target:
            if args.target.startswith('http://') or args.target.startswith('https://'):
                url = args.target
                try:
                    with urllib.request.urlopen(url, timeout=30) as response:
                        content = response.read().decode('utf-8')
                except Exception as e:
                    print(f"{Colors.RED}Error fetching URL: {e}{Colors.RESET}", file=sys.stderr)
                    sys.exit(1)
            else:
                # File path
                path = Path(args.target)
                if not path.exists():
                    print(f"{Colors.RED}File not found: {args.target}{Colors.RESET}", file=sys.stderr)
                    sys.exit(1)
                content = path.read_text()
        else:
            print(f"{Colors.RED}Please provide a URL, file path, or --content{Colors.RESET}", file=sys.stderr)
            sys.exit(1)
        
        # Run scan
        result = scan_skill(content, url)
        print_result(result, json_output=args.json)
        
        # Exit with code based on risk level
        risk_codes = {
            'clean': 0,
            'low': 0,
            'medium': 1,
            'high': 2,
            'critical': 3,
        }
        sys.exit(risk_codes.get(result['risk_level'], 1))


if __name__ == '__main__':
    main()
