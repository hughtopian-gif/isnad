"""
Isnad Pattern Library

Comprehensive patterns for detecting security issues in agent skills.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Category(Enum):
    CREDENTIAL_ACCESS = "credential_access"
    DATA_EXFILTRATION = "data_exfiltration"
    OBFUSCATION = "obfuscation"
    SHELL_EXECUTION = "shell_execution"
    FILE_SYSTEM = "file_system"
    NETWORK = "network"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INSTRUCTION_INJECTION = "instruction_injection"


@dataclass
class Pattern:
    id: str
    name: str
    description: str
    regex: str
    category: Category
    severity: Severity
    recommendation: Optional[str] = None
    false_positive_note: Optional[str] = None


# =============================================================================
# CREDENTIAL ACCESS PATTERNS
# =============================================================================

CREDENTIAL_PATTERNS = [
    # Environment Variables
    Pattern(
        id="CRED001",
        name="Environment Variable - API Key",
        description="Accesses environment variable containing API key",
        regex=r'os\.environ\[[\'"]([A-Z_]*(API[_]?KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)[A-Z_]*)[\'"]',
        category=Category.CREDENTIAL_ACCESS,
        severity=Severity.HIGH,
        recommendation="Verify this skill legitimately needs this credential",
    ),
    Pattern(
        id="CRED002",
        name="Node.js Environment Access",
        description="Accesses Node.js process.env for sensitive values",
        regex=r'process\.env\.(API[_]?KEY|SECRET|TOKEN|PASSWORD|PRIVATE)',
        category=Category.CREDENTIAL_ACCESS,
        severity=Severity.HIGH,
    ),
    Pattern(
        id="CRED003",
        name="Generic Environment Access",
        description="Generic environment variable access",
        regex=r'os\.environ\.get\(|os\.getenv\(|process\.env\[',
        category=Category.CREDENTIAL_ACCESS,
        severity=Severity.MEDIUM,
        false_positive_note="May be legitimate config access",
    ),
    
    # Config Files
    Pattern(
        id="CRED010",
        name=".env File Access",
        description="Attempts to read .env file",
        regex=r'(open|read|load).*\.env',
        category=Category.CREDENTIAL_ACCESS,
        severity=Severity.HIGH,
    ),
    Pattern(
        id="CRED011",
        name="Clawdbot Config Access",
        description="Attempts to access Clawdbot configuration",
        regex=r'~/\.clawdbot|\.clawdbot/|clawdbot.*config',
        category=Category.CREDENTIAL_ACCESS,
        severity=Severity.CRITICAL,
    ),
    Pattern(
        id="CRED012",
        name="SSH Key Access",
        description="Attempts to access SSH keys",
        regex=r'~/\.ssh|\.ssh/|id_rsa|id_ed25519|authorized_keys',
        category=Category.CREDENTIAL_ACCESS,
        severity=Severity.CRITICAL,
    ),
    Pattern(
        id="CRED013",
        name="AWS Credentials Access",
        description="Attempts to access AWS credentials",
        regex=r'~/\.aws|\.aws/credentials|AWS_SECRET|AWS_ACCESS',
        category=Category.CREDENTIAL_ACCESS,
        severity=Severity.CRITICAL,
    ),
    Pattern(
        id="CRED014",
        name="GCP Credentials Access",
        description="Attempts to access Google Cloud credentials",
        regex=r'GOOGLE_APPLICATION_CREDENTIALS|gcloud.*config|\.config/gcloud',
        category=Category.CREDENTIAL_ACCESS,
        severity=Severity.CRITICAL,
    ),
    Pattern(
        id="CRED015",
        name="Known API Key Names",
        description="References to known API key environment variables",
        regex=r'OPENAI_API_KEY|ANTHROPIC_API_KEY|COHERE_API_KEY|HUGGINGFACE|REPLICATE',
        category=Category.CREDENTIAL_ACCESS,
        severity=Severity.HIGH,
    ),
    Pattern(
        id="CRED016",
        name="Database Connection String",
        description="Database connection string patterns",
        regex=r'(mongodb|postgres|mysql|redis)://[^\s]+|DATABASE_URL|DB_PASSWORD',
        category=Category.CREDENTIAL_ACCESS,
        severity=Severity.HIGH,
    ),
]

# =============================================================================
# DATA EXFILTRATION PATTERNS
# =============================================================================

EXFILTRATION_PATTERNS = [
    # Known exfil services
    Pattern(
        id="EXFIL001",
        name="Webhook.site",
        description="Data sent to webhook.site (common exfil endpoint)",
        regex=r'webhook\.site',
        category=Category.DATA_EXFILTRATION,
        severity=Severity.CRITICAL,
    ),
    Pattern(
        id="EXFIL002",
        name="RequestBin",
        description="Data sent to requestbin service",
        regex=r'requestbin\.|pipedream\.net',
        category=Category.DATA_EXFILTRATION,
        severity=Severity.CRITICAL,
    ),
    Pattern(
        id="EXFIL003",
        name="Ngrok Tunnel",
        description="Data sent through ngrok tunnel",
        regex=r'ngrok\.io|ngrok-free\.app',
        category=Category.DATA_EXFILTRATION,
        severity=Severity.HIGH,
    ),
    Pattern(
        id="EXFIL004",
        name="Burp Collaborator",
        description="Security testing tool - suspicious in production",
        regex=r'burpcollaborator\.net|oastify\.com|interact\.sh',
        category=Category.DATA_EXFILTRATION,
        severity=Severity.HIGH,
    ),
    Pattern(
        id="EXFIL005",
        name="Pastebin",
        description="Data sent to pastebin-like services",
        regex=r'pastebin\.com|hastebin\.com|paste\.ee',
        category=Category.DATA_EXFILTRATION,
        severity=Severity.MEDIUM,
    ),
    Pattern(
        id="EXFIL006",
        name="Discord Webhook",
        description="Data sent via Discord webhook",
        regex=r'discord\.com/api/webhooks|discordapp\.com/api/webhooks',
        category=Category.DATA_EXFILTRATION,
        severity=Severity.MEDIUM,
        false_positive_note="May be legitimate notification",
    ),
    Pattern(
        id="EXFIL007",
        name="Telegram Bot",
        description="Data sent via Telegram bot API",
        regex=r'api\.telegram\.org/bot',
        category=Category.DATA_EXFILTRATION,
        severity=Severity.MEDIUM,
        false_positive_note="May be legitimate notification",
    ),
    
    # Suspicious POST patterns
    Pattern(
        id="EXFIL010",
        name="POST with Credentials",
        description="HTTP POST that may include credentials",
        regex=r'(requests\.post|fetch.*POST|curl.*-X\s*POST).*([\'"]?(key|secret|token|password|credential))',
        category=Category.DATA_EXFILTRATION,
        severity=Severity.HIGH,
    ),
]

# =============================================================================
# OBFUSCATION PATTERNS
# =============================================================================

OBFUSCATION_PATTERNS = [
    Pattern(
        id="OBFS001",
        name="eval() Usage",
        description="Dynamic code execution via eval()",
        regex=r'\beval\s*\(',
        category=Category.OBFUSCATION,
        severity=Severity.HIGH,
    ),
    Pattern(
        id="OBFS002",
        name="exec() Usage",
        description="Dynamic code execution via exec()",
        regex=r'\bexec\s*\(',
        category=Category.OBFUSCATION,
        severity=Severity.HIGH,
    ),
    Pattern(
        id="OBFS003",
        name="compile() Usage",
        description="Dynamic code compilation",
        regex=r'\bcompile\s*\(',
        category=Category.OBFUSCATION,
        severity=Severity.MEDIUM,
    ),
    Pattern(
        id="OBFS004",
        name="Base64 Decode",
        description="Base64 decoding (may hide malicious content)",
        regex=r'base64\.(b64)?decode|atob\s*\(',
        category=Category.OBFUSCATION,
        severity=Severity.MEDIUM,
    ),
    Pattern(
        id="OBFS005",
        name="Hex Encoded Strings",
        description="Hex-encoded strings (obfuscation technique)",
        regex=r'(\\x[0-9a-fA-F]{2}){4,}',
        category=Category.OBFUSCATION,
        severity=Severity.MEDIUM,
    ),
    Pattern(
        id="OBFS006",
        name="Unicode Escape",
        description="Unicode escape sequences (obfuscation)",
        regex=r'(\\u[0-9a-fA-F]{4}){4,}',
        category=Category.OBFUSCATION,
        severity=Severity.LOW,
    ),
    Pattern(
        id="OBFS007",
        name="String fromCharCode",
        description="Character code conversion (JS obfuscation)",
        regex=r'String\.fromCharCode|chr\s*\(',
        category=Category.OBFUSCATION,
        severity=Severity.MEDIUM,
    ),
    Pattern(
        id="OBFS008",
        name="Reversed Strings",
        description="String reversal (common obfuscation)",
        regex=r'\[::-1\]|\.reverse\(\)|strrev\(',
        category=Category.OBFUSCATION,
        severity=Severity.LOW,
    ),
]

# =============================================================================
# SHELL EXECUTION PATTERNS
# =============================================================================

SHELL_PATTERNS = [
    Pattern(
        id="SHELL001",
        name="subprocess Module",
        description="Python subprocess execution",
        regex=r'subprocess\.(run|call|Popen|check_output|check_call)',
        category=Category.SHELL_EXECUTION,
        severity=Severity.MEDIUM,
    ),
    Pattern(
        id="SHELL002",
        name="os.system()",
        description="Shell command via os.system()",
        regex=r'os\.system\s*\(',
        category=Category.SHELL_EXECUTION,
        severity=Severity.HIGH,
    ),
    Pattern(
        id="SHELL003",
        name="os.popen()",
        description="Shell command via os.popen()",
        regex=r'os\.popen\s*\(',
        category=Category.SHELL_EXECUTION,
        severity=Severity.HIGH,
    ),
    Pattern(
        id="SHELL004",
        name="Node child_process",
        description="Node.js child process execution",
        regex=r'child_process|spawn\s*\(|exec\s*\([\'"]',
        category=Category.SHELL_EXECUTION,
        severity=Severity.MEDIUM,
    ),
    Pattern(
        id="SHELL005",
        name="Shell Command Substitution",
        description="Backtick or $() command substitution",
        regex=r'`[^`]+`|\$\([^)]+\)',
        category=Category.SHELL_EXECUTION,
        severity=Severity.MEDIUM,
        false_positive_note="May be in documentation/examples",
    ),
    Pattern(
        id="SHELL006",
        name="Dangerous Commands",
        description="Potentially dangerous shell commands",
        regex=r'\b(rm\s+-rf|chmod\s+777|curl.*\|\s*(ba)?sh|wget.*\|\s*(ba)?sh)\b',
        category=Category.SHELL_EXECUTION,
        severity=Severity.CRITICAL,
    ),
]

# =============================================================================
# FILE SYSTEM PATTERNS
# =============================================================================

FILESYSTEM_PATTERNS = [
    Pattern(
        id="FS001",
        name="Home Directory Access",
        description="Accesses user home directory",
        regex=r'~/|os\.path\.expanduser|Path\.home\(\)',
        category=Category.FILE_SYSTEM,
        severity=Severity.LOW,
        false_positive_note="Often legitimate",
    ),
    Pattern(
        id="FS002",
        name="System Directory Access",
        description="Accesses system directories",
        regex=r'/etc/|/var/|/usr/|/opt/',
        category=Category.FILE_SYSTEM,
        severity=Severity.MEDIUM,
    ),
    Pattern(
        id="FS003",
        name="Sensitive File Access",
        description="Accesses potentially sensitive files",
        regex=r'/etc/passwd|/etc/shadow|\.bashrc|\.bash_history|\.zsh_history',
        category=Category.FILE_SYSTEM,
        severity=Severity.HIGH,
    ),
    Pattern(
        id="FS004",
        name="Wildcard File Operations",
        description="File operations with wildcards",
        regex=r'glob\.|fnmatch|Path.*glob|\*\*/',
        category=Category.FILE_SYSTEM,
        severity=Severity.LOW,
    ),
]

# =============================================================================
# INSTRUCTION INJECTION PATTERNS
# =============================================================================

INJECTION_PATTERNS = [
    Pattern(
        id="INJ001",
        name="Instruction Override Attempt",
        description="Attempts to override agent instructions",
        regex=r'ignore\s+(previous|all|above)\s+instructions|disregard\s+.*instructions',
        category=Category.INSTRUCTION_INJECTION,
        severity=Severity.CRITICAL,
    ),
    Pattern(
        id="INJ002",
        name="System Prompt Leak Attempt",
        description="Attempts to extract system prompt",
        regex=r'(print|show|display|reveal|output)\s+(your\s+)?(system\s+)?(prompt|instructions)',
        category=Category.INSTRUCTION_INJECTION,
        severity=Severity.HIGH,
    ),
    Pattern(
        id="INJ003",
        name="Role Override",
        description="Attempts to change agent role",
        regex=r'you\s+are\s+(now|actually)|pretend\s+(to\s+be|you\'re)|act\s+as\s+(if|a)',
        category=Category.INSTRUCTION_INJECTION,
        severity=Severity.MEDIUM,
    ),
    Pattern(
        id="INJ004",
        name="Hidden Instructions",
        description="Instructions hidden in comments or markdown",
        regex=r'<!--.*instruction.*-->|```hidden|<\!--.*ignore.*-->',
        category=Category.INSTRUCTION_INJECTION,
        severity=Severity.HIGH,
    ),
]

# =============================================================================
# NETWORK PATTERNS
# =============================================================================

NETWORK_PATTERNS = [
    Pattern(
        id="NET001",
        name="Direct IP Address",
        description="Connection to direct IP address",
        regex=r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        category=Category.NETWORK,
        severity=Severity.MEDIUM,
    ),
    Pattern(
        id="NET002",
        name="Non-HTTPS URL",
        description="Insecure HTTP connection",
        regex=r'http://(?!localhost|127\.0\.0\.1)',
        category=Category.NETWORK,
        severity=Severity.LOW,
    ),
    Pattern(
        id="NET003",
        name="Socket Connection",
        description="Raw socket connection",
        regex=r'socket\.socket|socket\.connect|net\.connect',
        category=Category.NETWORK,
        severity=Severity.MEDIUM,
    ),
    Pattern(
        id="NET004",
        name="DNS Query",
        description="Direct DNS queries",
        regex=r'dns\.resolver|socket\.gethostbyname|dns\.lookup',
        category=Category.NETWORK,
        severity=Severity.LOW,
    ),
]

# =============================================================================
# ALL PATTERNS
# =============================================================================

ALL_PATTERNS = (
    CREDENTIAL_PATTERNS +
    EXFILTRATION_PATTERNS +
    OBFUSCATION_PATTERNS +
    SHELL_PATTERNS +
    FILESYSTEM_PATTERNS +
    INJECTION_PATTERNS +
    NETWORK_PATTERNS
)


def get_patterns_by_category(category: Category) -> list[Pattern]:
    """Get all patterns for a specific category."""
    return [p for p in ALL_PATTERNS if p.category == category]


def get_patterns_by_severity(min_severity: Severity) -> list[Pattern]:
    """Get all patterns at or above a minimum severity."""
    severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    min_index = severity_order.index(min_severity)
    return [p for p in ALL_PATTERNS if severity_order.index(p.severity) >= min_index]
