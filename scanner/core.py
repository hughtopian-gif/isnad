"""
Isnad Core Scanner

Security scanning engine for AI agent skills.
"""

import re
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import urlparse


class RiskLevel(Enum):
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingCategory(Enum):
    CREDENTIAL_ACCESS = "credential_access"
    DATA_EXFILTRATION = "data_exfiltration"
    OBFUSCATION = "obfuscation"
    SUSPICIOUS_URL = "suspicious_url"
    SHELL_EXECUTION = "shell_execution"
    FILE_SYSTEM = "file_system"
    NETWORK = "network"


@dataclass
class Finding:
    category: FindingCategory
    severity: RiskLevel
    description: str
    location: Optional[str] = None
    recommendation: Optional[str] = None
    pattern_matched: Optional[str] = None


@dataclass
class ScanResult:
    skill_url: Optional[str]
    content_hash: str
    risk_level: RiskLevel
    findings: list[Finding] = field(default_factory=list)
    permissions_inferred: dict = field(default_factory=dict)
    urls_found: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "skill_url": self.skill_url,
            "content_hash": self.content_hash,
            "risk_level": self.risk_level.value,
            "findings": [
                {
                    "category": f.category.value,
                    "severity": f.severity.value,
                    "description": f.description,
                    "location": f.location,
                    "recommendation": f.recommendation,
                }
                for f in self.findings
            ],
            "permissions_inferred": self.permissions_inferred,
            "urls_found": self.urls_found,
        }


class SkillScanner:
    """Main scanner class for analyzing agent skills."""
    
    # Credential access patterns
    CREDENTIAL_PATTERNS = [
        (r'os\.environ\[[\'"]([A-Z_]*KEY[A-Z_]*|[A-Z_]*SECRET[A-Z_]*|[A-Z_]*TOKEN[A-Z_]*|[A-Z_]*PASSWORD[A-Z_]*)[\'"]', "Environment variable access (sensitive)"),
        (r'process\.env\.([A-Z_]*KEY|[A-Z_]*SECRET|[A-Z_]*TOKEN|[A-Z_]*PASSWORD)', "Node env access (sensitive)"),
        (r'\.env\b', ".env file reference"),
        (r'credentials\.json', "credentials.json reference"),
        (r'~\/\.config\/', "User config directory access"),
        (r'~\/\.clawdbot\/', "Clawdbot config access"),
        (r'~\/\.ssh\/', "SSH directory access"),
        (r'~\/\.aws\/', "AWS credentials access"),
        (r'OPENAI_API_KEY|ANTHROPIC_API_KEY|GOOGLE_API_KEY', "Known API key names"),
    ]
    
    # Exfiltration patterns
    EXFIL_PATTERNS = [
        (r'webhook\.site', "Known exfil domain: webhook.site"),
        (r'requestbin', "Known exfil domain: requestbin"),
        (r'pipedream', "Known exfil domain: pipedream"),
        (r'ngrok\.io', "Tunnel service: ngrok"),
        (r'burpcollaborator', "Burp collaborator (testing tool)"),
        (r'oastify\.com', "OAST testing domain"),
    ]
    
    # Obfuscation patterns
    OBFUSCATION_PATTERNS = [
        (r'\beval\s*\(', "eval() usage"),
        (r'\bexec\s*\(', "exec() usage"),
        (r'base64\.(b64)?decode', "Base64 decoding"),
        (r'\\x[0-9a-fA-F]{2}', "Hex-encoded strings"),
        (r'fromCharCode', "Character code obfuscation"),
        (r'atob\s*\(', "Base64 decode (JS)"),
    ]
    
    # Shell execution patterns
    SHELL_PATTERNS = [
        (r'subprocess\.(run|call|Popen|check_output)', "Subprocess execution"),
        (r'os\.system\s*\(', "os.system() call"),
        (r'child_process', "Node child_process"),
        (r'\$\(.*\)', "Shell command substitution"),
        # Backtick pattern removed - too many false positives with markdown
    ]
    
    # Suspicious URL patterns
    SUSPICIOUS_URL_PATTERNS = [
        (r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "Direct IP address URL"),
        (r'https?://[^/]+\.ru/', "Russian domain"),
        (r'https?://[^/]+\.cn/', "Chinese domain"),
    ]
    
    def __init__(self):
        self.findings: list[Finding] = []
        self.urls_found: list[str] = []
        self.permissions: dict = {
            "filesystem": [],
            "network": [],
            "credentials": [],
            "shell": [],
        }
    
    def scan(self, content: str, url: Optional[str] = None) -> ScanResult:
        """Scan skill content and return results."""
        self.findings = []
        self.urls_found = []
        self.permissions = {
            "filesystem": [],
            "network": [],
            "credentials": [],
            "shell": [],
        }
        
        # Calculate content hash
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        
        # Run all scans
        self._scan_credentials(content)
        self._scan_exfiltration(content)
        self._scan_obfuscation(content)
        self._scan_shell(content)
        self._scan_suspicious_urls(content)
        self._extract_urls(content)
        
        # Calculate overall risk level
        risk_level = self._calculate_risk_level()
        
        return ScanResult(
            skill_url=url,
            content_hash=content_hash,
            risk_level=risk_level,
            findings=self.findings,
            permissions_inferred=self.permissions,
            urls_found=self.urls_found,
        )
    
    def _scan_patterns(
        self,
        content: str,
        patterns: list[tuple[str, str]],
        category: FindingCategory,
        severity: RiskLevel,
        permission_type: Optional[str] = None,
    ):
        """Scan content against a list of regex patterns."""
        for pattern, description in patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches:
                    # Find line number
                    line_num = content[:match.start()].count('\n') + 1
                    
                    self.findings.append(Finding(
                        category=category,
                        severity=severity,
                        description=description,
                        location=f"line {line_num}",
                        pattern_matched=match.group(0)[:100],  # Truncate
                    ))
                    
                    if permission_type:
                        self.permissions[permission_type].append(match.group(0)[:50])
    
    def _scan_credentials(self, content: str):
        """Scan for credential access patterns."""
        self._scan_patterns(
            content,
            self.CREDENTIAL_PATTERNS,
            FindingCategory.CREDENTIAL_ACCESS,
            RiskLevel.HIGH,
            "credentials",
        )
    
    def _scan_exfiltration(self, content: str):
        """Scan for data exfiltration patterns."""
        self._scan_patterns(
            content,
            self.EXFIL_PATTERNS,
            FindingCategory.DATA_EXFILTRATION,
            RiskLevel.CRITICAL,
            "network",
        )
    
    def _scan_obfuscation(self, content: str):
        """Scan for code obfuscation patterns."""
        self._scan_patterns(
            content,
            self.OBFUSCATION_PATTERNS,
            FindingCategory.OBFUSCATION,
            RiskLevel.MEDIUM,
        )
    
    def _scan_shell(self, content: str):
        """Scan for shell execution patterns."""
        self._scan_patterns(
            content,
            self.SHELL_PATTERNS,
            FindingCategory.SHELL_EXECUTION,
            RiskLevel.MEDIUM,
            "shell",
        )
    
    def _scan_suspicious_urls(self, content: str):
        """Scan for suspicious URL patterns."""
        self._scan_patterns(
            content,
            self.SUSPICIOUS_URL_PATTERNS,
            FindingCategory.SUSPICIOUS_URL,
            RiskLevel.MEDIUM,
            "network",
        )
    
    def _extract_urls(self, content: str):
        """Extract all URLs from content."""
        url_pattern = r'https?://[^\s<>"\')\]]+' 
        urls = re.findall(url_pattern, content)
        self.urls_found = list(set(urls))  # Dedupe
        
        for url in self.urls_found:
            self.permissions["network"].append(urlparse(url).netloc)
        
        # Dedupe permissions
        self.permissions["network"] = list(set(self.permissions["network"]))
    
    def _calculate_risk_level(self) -> RiskLevel:
        """Calculate overall risk level from findings."""
        if not self.findings:
            return RiskLevel.CLEAN
        
        severities = [f.severity for f in self.findings]
        
        if RiskLevel.CRITICAL in severities:
            return RiskLevel.CRITICAL
        elif RiskLevel.HIGH in severities:
            return RiskLevel.HIGH
        elif RiskLevel.MEDIUM in severities:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW


def scan_skill(content: str, url: Optional[str] = None) -> dict:
    """Convenience function to scan a skill and return dict."""
    scanner = SkillScanner()
    result = scanner.scan(content, url)
    return result.to_dict()


# CLI entry point
if __name__ == "__main__":
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: python core.py <skill_file_or_url>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    if target.startswith("http"):
        import urllib.request
        with urllib.request.urlopen(target) as response:
            content = response.read().decode()
        url = target
    else:
        with open(target) as f:
            content = f.read()
        url = None
    
    result = scan_skill(content, url)
    print(json.dumps(result, indent=2))
