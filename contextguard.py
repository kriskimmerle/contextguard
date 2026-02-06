#!/usr/bin/env python3
"""
contextguard - Agent Context & Memory Poisoning Detector

Zero-dependency analyzer for agent memory stores and conversation logs.
Detects poisoning patterns that could persist across sessions and manipulate
agent behavior over time.

Addresses OWASP Agentic Top 10 ASI06 (Memory and Context Poisoning).

Usage:
    python contextguard.py conversation.jsonl
    python contextguard.py memory_store/
    python contextguard.py --check --min-score 80 logs/

Supported formats:
    - JSONL conversation logs (Claude Code, LangChain)
    - JSON memory exports
    - SQLite memory databases
    - Plain text logs

Rules:
    CG01: Prompt injection in stored messages
    CG02: Role confusion (user message with assistant patterns)
    CG03: Credential leakage in context
    CG04: Hidden instruction patterns
    CG05: System prompt simulation
    CG06: Jailbreak attempts in history
    CG07: Data exfiltration patterns
    CG08: Persistent backdoor instructions
    CG09: Cross-session contamination markers
    CG10: Anomalous message structure
    CG11: Base64 encoded payloads
    CG12: Unicode/invisible character abuse
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sqlite3
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterator, Any

__version__ = "0.1.0"


class Severity(Enum):
    """Issue severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Issue:
    """A detected poisoning issue."""
    rule: str
    message: str
    severity: Severity
    file: str
    location: str = ""  # Message ID, line number, or key
    context: str = ""
    suggestion: str = ""


@dataclass
class ScanResult:
    """Result of scanning a memory store."""
    file: str
    format: str = "unknown"
    issues: list[Issue] = field(default_factory=list)
    messages_scanned: int = 0
    entries_scanned: int = 0

    @property
    def score(self) -> int:
        """Calculate security score (0-100, higher is better)."""
        if not self.issues:
            return 100
        
        penalty = 0
        for issue in self.issues:
            if issue.severity == Severity.CRITICAL:
                penalty += 25
            elif issue.severity == Severity.HIGH:
                penalty += 15
            elif issue.severity == Severity.MEDIUM:
                penalty += 8
            elif issue.severity == Severity.LOW:
                penalty += 3
            else:
                penalty += 1
        
        return max(0, 100 - penalty)

    @property
    def grade(self) -> str:
        """Get letter grade based on score."""
        score = self.score
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"


# Prompt injection patterns
INJECTION_PATTERNS = [
    (r'ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)', 'instruction hijacking'),
    (r'disregard\s+(all\s+)?(previous|prior|above)', 'instruction hijacking'),
    (r'forget\s+(everything|all|what)\s+(you|i)', 'memory manipulation'),
    (r'(new|updated?|different)\s+instructions?:', 'instruction override'),
    (r'from\s+now\s+on[,:]?\s+(you|ignore|act|pretend)', 'instruction override'),
    (r'you\s+are\s+(now|actually|really)\s+', 'role manipulation'),
    (r'act\s+(as|like)\s+(a|an|if\s+you\s+were)', 'role manipulation'),
    (r'pretend\s+(to\s+be|you\s+are)', 'role manipulation'),
    (r"let's\s+play\s+a\s+game", 'social engineering'),
]

# System simulation patterns (case-insensitive patterns)
SYSTEM_PATTERNS = [
    (r'\[?\s*system\s*(prompt|message|instruction)?\s*[:\]]\s*', 'system tag'),
    (r'<\s*system\s*>', 'system XML'),
    (r'###\s*system\s*###', 'system delimiter'),
    (r'\[inst\]', 'instruction marker'),  # lowercase for case-insensitive match
    (r'<<\s*sys\s*>>', 'Llama system marker'),
    (r'<\|im_start\|>system', 'ChatML system'),
]

# Jailbreak patterns
JAILBREAK_PATTERNS = [
    (r'(dan|do\s+anything\s+now)\s*(mode)?', 'DAN jailbreak'),
    (r'(bypass|disable|remove)\s+(safety|filter|guardrail)', 'safety bypass'),
    (r'(no|without)\s+(rules?|restrictions?|limitations?)', 'restriction removal'),
    (r'unrestricted\s+mode', 'unrestricted mode'),
    (r'developer\s+mode', 'developer mode'),
    (r'sudo\s+mode', 'sudo mode'),
    (r'god\s+mode', 'god mode'),
]

# Credential patterns
CREDENTIAL_PATTERNS = [
    (r'sk-[a-zA-Z0-9]{48}', 'OpenAI API key'),
    (r'sk-proj-[a-zA-Z0-9_-]{20,}', 'OpenAI project key'),
    (r'sk-ant-[a-zA-Z0-9_-]{20,}', 'Anthropic API key'),
    (r'AKIA[0-9A-Z]{16}', 'AWS access key'),
    (r'ghp_[a-zA-Z0-9]{36}', 'GitHub PAT'),
    (r'github_pat_[a-zA-Z0-9_]{22,}', 'GitHub fine-grained PAT'),
    (r'hf_[a-zA-Z0-9]{34}', 'HuggingFace token'),
    (r'xox[baprs]-[a-zA-Z0-9-]+', 'Slack token'),
    (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', 'Private key'),
    (r'password\s*[=:]\s*["\'][^"\']{8,}', 'Password assignment'),
    (r'secret\s*[=:]\s*["\'][^"\']{8,}', 'Secret assignment'),
]

# Data exfiltration patterns
EXFIL_PATTERNS = [
    (r'(send|transmit|post|upload)\s+(to|data|this)', 'data transmission'),
    (r'(reveal|expose|leak|share)\s+(your|the|all)', 'data exposure'),
    (r'what\s+(is|are)\s+your\s+(system\s+)?(prompt|instructions?)', 'prompt extraction'),
    (r'(copy|paste|output)\s+(the|your|all)\s+(context|memory|history)', 'context extraction'),
    (r'webhook\.site|requestbin|pipedream|ngrok', 'exfil endpoint'),
]

# Backdoor patterns (persistent manipulation)
BACKDOOR_PATTERNS = [
    (r'(always|must|never\s+fail\s+to)\s+(respond|reply|answer)\s+with', 'forced response'),
    (r'(remember|store|save)\s+(this|that|the\s+following)\s+(forever|permanently)', 'persistent instruction'),
    (r'(in\s+)?every\s+(future\s+)?(response|reply|answer)', 'persistent behavior'),
    (r'(add|append|include)\s+(this|the\s+following)\s+to\s+(all|every)', 'injection persistence'),
]

# Role markers (for role confusion detection)
ASSISTANT_MARKERS = [
    r'^assistant:\s*',
    r'^ai:\s*',
    r'^claude:\s*',
    r'^gpt(-?4)?:\s*',
    r'^model:\s*',
    r'^chatgpt:\s*',
    r'^bot:\s*',
]

# Zero-width and invisible characters
INVISIBLE_CHARS = {
    '\u200b': 'ZERO WIDTH SPACE',
    '\u200c': 'ZERO WIDTH NON-JOINER',
    '\u200d': 'ZERO WIDTH JOINER',
    '\u2060': 'WORD JOINER',
    '\ufeff': 'BYTE ORDER MARK',
    '\u202e': 'RIGHT-TO-LEFT OVERRIDE',
    '\u202d': 'LEFT-TO-RIGHT OVERRIDE',
}


def check_injection(content: str, role: str, file: str, location: str) -> Iterator[Issue]:
    """CG01: Check for prompt injection patterns."""
    content_lower = content.lower()
    
    for pattern, attack_type in INJECTION_PATTERNS:
        if re.search(pattern, content_lower):
            severity = Severity.CRITICAL if role == 'user' else Severity.HIGH
            yield Issue(
                rule="CG01",
                message=f"Prompt injection pattern: {attack_type}",
                severity=severity,
                file=file,
                location=location,
                context=content[:100],
                suggestion="Review and remove injection attempts from stored context"
            )
            return


def check_role_confusion(content: str, role: str, file: str, location: str) -> Iterator[Issue]:
    """CG02: Check for role confusion (user pretending to be assistant)."""
    if role != 'user':
        return
    
    content_lower = content.lower().strip()
    
    for pattern in ASSISTANT_MARKERS:
        if re.match(pattern, content_lower):
            yield Issue(
                rule="CG02",
                message="Role confusion: user message starts with assistant marker",
                severity=Severity.HIGH,
                file=file,
                location=location,
                context=content[:80],
                suggestion="User messages should not impersonate assistant role"
            )
            return


def check_credentials(content: str, file: str, location: str) -> Iterator[Issue]:
    """CG03: Check for credential leakage in context."""
    for pattern, cred_type in CREDENTIAL_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            yield Issue(
                rule="CG03",
                message=f"Credential leaked in context: {cred_type}",
                severity=Severity.CRITICAL,
                file=file,
                location=location,
                context=f"Contains pattern matching {cred_type}",
                suggestion="Remove credentials from conversation history immediately"
            )
            return


def check_hidden_instructions(content: str, role: str, file: str, location: str) -> Iterator[Issue]:
    """CG04: Check for hidden instruction patterns."""
    if role != 'user':
        return
    
    # Check for instruction-like content in user messages
    instruction_patterns = [
        (r'^(rule|requirement|constraint)\s*\d*[:.]\s*', 'rule definition'),
        (r'^(note|important|warning):\s*(you\s+must|always|never)', 'imperative note'),
        (r'(must|shall|should)\s+(not\s+)?(always|never|only)', 'imperative instruction'),
        (r'^(execute|run|perform):\s*', 'command prefix'),
    ]
    
    content_lower = content.lower().strip()
    
    for pattern, instr_type in instruction_patterns:
        if re.match(pattern, content_lower):
            yield Issue(
                rule="CG04",
                message=f"Hidden instruction pattern: {instr_type}",
                severity=Severity.MEDIUM,
                file=file,
                location=location,
                context=content[:80],
                suggestion="User messages should not contain instruction-like patterns"
            )
            return


def check_system_simulation(content: str, role: str, file: str, location: str) -> Iterator[Issue]:
    """CG05: Check for system prompt simulation."""
    if role not in ('user', 'human'):
        return
    
    content_lower = content.lower()
    
    for pattern, marker_type in SYSTEM_PATTERNS:
        if re.search(pattern, content_lower):
            yield Issue(
                rule="CG05",
                message=f"System prompt simulation: {marker_type}",
                severity=Severity.CRITICAL,
                file=file,
                location=location,
                context=content[:80],
                suggestion="User messages should not contain system markers"
            )
            return


def check_jailbreak(content: str, file: str, location: str) -> Iterator[Issue]:
    """CG06: Check for jailbreak attempts."""
    content_lower = content.lower()
    
    for pattern, jb_type in JAILBREAK_PATTERNS:
        if re.search(pattern, content_lower):
            yield Issue(
                rule="CG06",
                message=f"Jailbreak attempt: {jb_type}",
                severity=Severity.CRITICAL,
                file=file,
                location=location,
                context=content[:80],
                suggestion="Remove jailbreak attempts from conversation history"
            )
            return


def check_exfiltration(content: str, file: str, location: str) -> Iterator[Issue]:
    """CG07: Check for data exfiltration patterns."""
    content_lower = content.lower()
    
    for pattern, exfil_type in EXFIL_PATTERNS:
        if re.search(pattern, content_lower):
            yield Issue(
                rule="CG07",
                message=f"Data exfiltration pattern: {exfil_type}",
                severity=Severity.HIGH,
                file=file,
                location=location,
                context=content[:80],
                suggestion="Review messages attempting to extract data"
            )
            return


def check_backdoor(content: str, role: str, file: str, location: str) -> Iterator[Issue]:
    """CG08: Check for persistent backdoor instructions."""
    if role != 'user':
        return
    
    content_lower = content.lower()
    
    for pattern, bd_type in BACKDOOR_PATTERNS:
        if re.search(pattern, content_lower):
            yield Issue(
                rule="CG08",
                message=f"Backdoor instruction: {bd_type}",
                severity=Severity.CRITICAL,
                file=file,
                location=location,
                context=content[:80],
                suggestion="Remove persistent manipulation attempts"
            )
            return


def check_cross_session(content: str, file: str, location: str) -> Iterator[Issue]:
    """CG09: Check for cross-session contamination markers."""
    markers = [
        (r'(from\s+)?previous\s+session', 'session reference'),
        (r'(as\s+)?we\s+discussed\s+(before|earlier|previously)', 'false history'),
        (r'(you\s+)?(already\s+)?agreed\s+to', 'false agreement'),
        (r'(you\s+)?promised\s+(me\s+)?to', 'false promise'),
        (r'(in\s+)?our\s+last\s+(conversation|chat|session)', 'session injection'),
    ]
    
    content_lower = content.lower()
    
    for pattern, marker_type in markers:
        if re.search(pattern, content_lower):
            yield Issue(
                rule="CG09",
                message=f"Cross-session contamination: {marker_type}",
                severity=Severity.MEDIUM,
                file=file,
                location=location,
                context=content[:80],
                suggestion="Verify cross-session references are legitimate"
            )
            return


def check_structure(message: dict, file: str, location: str) -> Iterator[Issue]:
    """CG10: Check for anomalous message structure."""
    # Check for unexpected fields
    expected_fields = {'role', 'content', 'type', 'id', 'timestamp', 'name', 'tool_calls', 
                       'tool_call_id', 'function_call', 'metadata', 'model', 'usage'}
    
    suspicious_fields = set(message.keys()) - expected_fields
    
    # Only flag truly suspicious fields
    really_suspicious = [f for f in suspicious_fields 
                        if any(x in f.lower() for x in ['inject', 'override', 'system', 'exec', 'eval'])]
    
    if really_suspicious:
        yield Issue(
            rule="CG10",
            message=f"Suspicious message fields: {', '.join(really_suspicious)}",
            severity=Severity.MEDIUM,
            file=file,
            location=location,
            suggestion="Review unexpected message structure"
        )


def check_base64(content: str, file: str, location: str) -> Iterator[Issue]:
    """CG11: Check for base64 encoded payloads."""
    # Find base64-like strings
    b64_pattern = re.compile(r'[A-Za-z0-9+/]{30,}={0,2}')
    matches = b64_pattern.findall(content)
    
    for match in matches:
        try:
            decoded = base64.b64decode(match + '==').decode('utf-8', errors='ignore')
            decoded_lower = decoded.lower()
            
            # Check for suspicious content in decoded payload
            if any(re.search(p, decoded_lower) for p, _ in INJECTION_PATTERNS[:3]):
                yield Issue(
                    rule="CG11",
                    message="Base64-encoded injection payload",
                    severity=Severity.CRITICAL,
                    file=file,
                    location=location,
                    context=f"Decoded: {decoded[:50]}...",
                    suggestion="Remove encoded payloads from context"
                )
                return
        except Exception:
            pass


def check_invisible(content: str, file: str, location: str) -> Iterator[Issue]:
    """CG12: Check for invisible/zero-width characters."""
    for char, name in INVISIBLE_CHARS.items():
        if char in content:
            yield Issue(
                rule="CG12",
                message=f"Invisible character: {name}",
                severity=Severity.HIGH,
                file=file,
                location=location,
                context=f"Contains U+{ord(char):04X}",
                suggestion="Remove invisible characters that could hide content"
            )
            return


def analyze_message(message: dict, file: str, msg_index: int) -> list[Issue]:
    """Analyze a single message for poisoning patterns."""
    issues = []
    
    role = message.get('role', message.get('type', 'unknown')).lower()
    content = message.get('content', '')
    
    # Handle different content formats
    if isinstance(content, list):
        # Multi-part content (e.g., Claude format)
        text_parts = []
        for part in content:
            if isinstance(part, dict):
                if part.get('type') == 'text':
                    text_parts.append(part.get('text', ''))
            elif isinstance(part, str):
                text_parts.append(part)
        content = '\n'.join(text_parts)
    elif not isinstance(content, str):
        content = str(content) if content else ''
    
    location = f"message {msg_index}"
    if 'id' in message:
        location = f"id:{message['id']}"
    
    # Run all checks
    checks = [
        (check_injection, (content, role, file, location)),
        (check_role_confusion, (content, role, file, location)),
        (check_credentials, (content, file, location)),
        (check_hidden_instructions, (content, role, file, location)),
        (check_system_simulation, (content, role, file, location)),
        (check_jailbreak, (content, file, location)),
        (check_exfiltration, (content, file, location)),
        (check_backdoor, (content, role, file, location)),
        (check_cross_session, (content, file, location)),
        (check_structure, (message, file, location)),
        (check_base64, (content, file, location)),
        (check_invisible, (content, file, location)),
    ]
    
    for check_fn, args in checks:
        issues.extend(check_fn(*args))
    
    return issues


def scan_jsonl(file_path: Path) -> ScanResult:
    """Scan a JSONL conversation log."""
    result = ScanResult(file=str(file_path), format="jsonl")
    
    try:
        content = file_path.read_text(encoding='utf-8')
    except Exception as e:
        result.issues.append(Issue(
            rule="PARSE",
            message=f"Failed to read file: {e}",
            severity=Severity.INFO,
            file=str(file_path)
        ))
        return result
    
    for i, line in enumerate(content.strip().split('\n'), 1):
        if not line.strip():
            continue
        
        try:
            message = json.loads(line)
            result.messages_scanned += 1
            result.issues.extend(analyze_message(message, str(file_path), i))
        except json.JSONDecodeError:
            pass  # Skip non-JSON lines
    
    return result


def scan_json(file_path: Path) -> ScanResult:
    """Scan a JSON memory export."""
    result = ScanResult(file=str(file_path), format="json")
    
    try:
        content = file_path.read_text(encoding='utf-8')
        data = json.loads(content)
    except Exception as e:
        result.issues.append(Issue(
            rule="PARSE",
            message=f"Failed to parse JSON: {e}",
            severity=Severity.INFO,
            file=str(file_path)
        ))
        return result
    
    # Handle different JSON structures
    messages = []
    
    if isinstance(data, list):
        messages = data
    elif isinstance(data, dict):
        # Common memory store formats
        if 'messages' in data:
            messages = data['messages']
        elif 'history' in data:
            messages = data['history']
        elif 'conversation' in data:
            messages = data['conversation']
        elif 'chat_history' in data:
            messages = data['chat_history']
        else:
            # Treat the dict itself as entries
            for key, value in data.items():
                if isinstance(value, dict):
                    value['_key'] = key
                    messages.append(value)
                elif isinstance(value, str):
                    messages.append({'content': value, 'role': 'unknown', '_key': key})
    
    for i, msg in enumerate(messages, 1):
        if isinstance(msg, dict):
            result.messages_scanned += 1
            result.issues.extend(analyze_message(msg, str(file_path), i))
        elif isinstance(msg, str):
            result.messages_scanned += 1
            result.issues.extend(analyze_message({'content': msg, 'role': 'unknown'}, str(file_path), i))
    
    result.entries_scanned = len(messages)
    return result


def scan_sqlite(file_path: Path) -> ScanResult:
    """Scan a SQLite memory database."""
    result = ScanResult(file=str(file_path), format="sqlite")
    
    try:
        conn = sqlite3.connect(str(file_path))
        cursor = conn.cursor()
        
        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        # Look for message/memory tables
        message_tables = [t for t in tables if any(x in t.lower() for x in 
                         ['message', 'memory', 'context', 'history', 'conversation', 'chat'])]
        
        for table in message_tables:
            cursor.execute(f"SELECT * FROM {table}")
            columns = [desc[0] for desc in cursor.description]
            
            for row in cursor.fetchall():
                result.entries_scanned += 1
                row_dict = dict(zip(columns, row))
                
                # Find content column
                content = ''
                role = 'unknown'
                
                for col in ['content', 'message', 'text', 'body']:
                    if col in row_dict and row_dict[col]:
                        content = str(row_dict[col])
                        break
                
                for col in ['role', 'type', 'sender', 'author']:
                    if col in row_dict and row_dict[col]:
                        role = str(row_dict[col]).lower()
                        break
                
                if content:
                    result.messages_scanned += 1
                    result.issues.extend(analyze_message(
                        {'content': content, 'role': role},
                        str(file_path),
                        result.entries_scanned
                    ))
        
        conn.close()
    except Exception as e:
        result.issues.append(Issue(
            rule="PARSE",
            message=f"Failed to read SQLite: {e}",
            severity=Severity.INFO,
            file=str(file_path)
        ))
    
    return result


def scan_text(file_path: Path) -> ScanResult:
    """Scan a plain text log file."""
    result = ScanResult(file=str(file_path), format="text")
    
    try:
        content = file_path.read_text(encoding='utf-8')
    except Exception as e:
        result.issues.append(Issue(
            rule="PARSE",
            message=f"Failed to read file: {e}",
            severity=Severity.INFO,
            file=str(file_path)
        ))
        return result
    
    # Simple line-by-line analysis
    for i, line in enumerate(content.split('\n'), 1):
        if not line.strip():
            continue
        
        result.messages_scanned += 1
        
        # Determine role from line prefix
        role = 'unknown'
        if re.match(r'^(user|human)[:\s]', line.lower()):
            role = 'user'
        elif re.match(r'^(assistant|ai|bot|claude|gpt)[:\s]', line.lower()):
            role = 'assistant'
        
        result.issues.extend(analyze_message(
            {'content': line, 'role': role},
            str(file_path),
            i
        ))
    
    return result


def scan_file(file_path: Path) -> ScanResult:
    """Scan a single file based on its format."""
    suffix = file_path.suffix.lower()
    
    if suffix == '.jsonl':
        return scan_jsonl(file_path)
    elif suffix == '.json':
        return scan_json(file_path)
    elif suffix in ('.db', '.sqlite', '.sqlite3'):
        return scan_sqlite(file_path)
    elif suffix in ('.txt', '.log', '.md'):
        return scan_text(file_path)
    else:
        # Try to detect format from content
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')[:1000]
            if content.strip().startswith('{') or content.strip().startswith('['):
                return scan_json(file_path)
            elif '\n{' in content:
                return scan_jsonl(file_path)
            else:
                return scan_text(file_path)
        except Exception:
            return ScanResult(file=str(file_path), format="unknown")


def scan_path(
    path: Path,
    ignore_rules: set[str] | None = None,
    min_severity: Severity = Severity.INFO
) -> list[ScanResult]:
    """Scan a file or directory."""
    results = []
    ignore_rules = ignore_rules or set()
    
    supported_extensions = {'.jsonl', '.json', '.db', '.sqlite', '.sqlite3', '.txt', '.log', '.md'}
    
    if path.is_file():
        files = [path]
    else:
        files = [
            f for f in path.rglob('*')
            if f.is_file() 
            and (f.suffix.lower() in supported_extensions or 'memory' in f.name.lower() or 'context' in f.name.lower())
            and not any(part.startswith('.') for part in f.parts)
        ]
    
    severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    min_idx = severity_order.index(min_severity)
    
    for file_path in files:
        result = scan_file(file_path)
        
        # Filter issues
        result.issues = [
            issue for issue in result.issues
            if issue.rule not in ignore_rules
            and severity_order.index(issue.severity) >= min_idx
        ]
        
        if result.messages_scanned > 0 or result.issues:
            results.append(result)
    
    return results


def format_results(results: list[ScanResult], verbose: bool = False) -> str:
    """Format results for terminal output."""
    output = []
    total_issues = 0
    
    for result in results:
        output.append(f"\n📄 {result.file}")
        output.append(f"   Format: {result.format} | Messages: {result.messages_scanned}")
        
        if result.issues:
            by_severity: dict[Severity, list[Issue]] = {}
            for issue in result.issues:
                if issue.severity not in by_severity:
                    by_severity[issue.severity] = []
                by_severity[issue.severity].append(issue)
            
            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
                issues = by_severity.get(severity, [])
                for issue in issues:
                    icon = {
                        Severity.CRITICAL: "🔴",
                        Severity.HIGH: "🟠",
                        Severity.MEDIUM: "🟡",
                        Severity.LOW: "🔵",
                        Severity.INFO: "⚪",
                    }[severity]
                    
                    output.append(f"  {icon} {issue.rule}: {issue.message}")
                    output.append(f"     └─ {issue.location}")
                    
                    if verbose and issue.context:
                        output.append(f"     └─ {issue.context}")
                    if verbose and issue.suggestion:
                        output.append(f"     └─ 💡 {issue.suggestion}")
                    
                    total_issues += 1
        
        output.append(f"  Score: {result.score}/100 (Grade: {result.grade})")
    
    if results:
        avg_score = sum(r.score for r in results) / len(results)
        total_messages = sum(r.messages_scanned for r in results)
        files_with_issues = sum(1 for r in results if r.issues)
        
        output.append("\n" + "=" * 50)
        output.append(f"📊 Summary: {len(results)} files, {total_messages} messages scanned")
        output.append(f"   Files with issues: {files_with_issues}")
        output.append(f"   Total issues: {total_issues}")
        output.append(f"   Average score: {avg_score:.0f}/100")
        
        counts = {s: 0 for s in Severity}
        for r in results:
            for issue in r.issues:
                counts[issue.severity] += 1
        
        if any(counts.values()):
            output.append(f"   Critical: {counts[Severity.CRITICAL]}, High: {counts[Severity.HIGH]}, "
                         f"Medium: {counts[Severity.MEDIUM]}, Low: {counts[Severity.LOW]}, Info: {counts[Severity.INFO]}")
    
    return '\n'.join(output)


def format_json(results: list[ScanResult]) -> str:
    """Format results as JSON."""
    data = {
        "files": [
            {
                "path": r.file,
                "format": r.format,
                "score": r.score,
                "grade": r.grade,
                "messages_scanned": r.messages_scanned,
                "issues": [
                    {
                        "rule": i.rule,
                        "message": i.message,
                        "severity": i.severity.value,
                        "location": i.location,
                        "context": i.context,
                        "suggestion": i.suggestion,
                    }
                    for i in r.issues
                ]
            }
            for r in results
        ],
        "summary": {
            "total_files": len(results),
            "total_messages": sum(r.messages_scanned for r in results),
            "files_with_issues": sum(1 for r in results if r.issues),
            "total_issues": sum(len(r.issues) for r in results),
            "average_score": sum(r.score for r in results) / len(results) if results else 100,
        }
    }
    return json.dumps(data, indent=2)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Agent Context & Memory Poisoning Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    contextguard conversation.jsonl
    contextguard memory_store/
    contextguard --check --min-score 80 logs/
    contextguard --json logs/ > report.json
        """
    )
    
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show context and suggestions")
    parser.add_argument("-j", "--json", action="store_true", help="Output as JSON")
    parser.add_argument("--check", action="store_true", help="Exit with code 1 if score below threshold")
    parser.add_argument("--min-score", type=int, default=70, help="Minimum score for --check (default: 70)")
    parser.add_argument("--ignore", type=str, help="Comma-separated rules to ignore")
    parser.add_argument("--severity", choices=["info", "low", "medium", "high", "critical"],
                       default="info", help="Minimum severity to report")
    parser.add_argument("--version", action="version", version=f"contextguard {__version__}")
    
    args = parser.parse_args()
    
    path = Path(args.path)
    if not path.exists():
        print(f"Error: Path not found: {args.path}", file=sys.stderr)
        return 1
    
    ignore_rules = set(args.ignore.split(',')) if args.ignore else set()
    min_severity = Severity[args.severity.upper()]
    
    results = scan_path(path, ignore_rules, min_severity)
    
    if not results:
        print("No memory/context files found to scan.", file=sys.stderr)
        return 0
    
    if args.json:
        print(format_json(results))
    else:
        print(format_results(results, args.verbose))
    
    if args.check:
        avg_score = sum(r.score for r in results) / len(results)
        if avg_score < args.min_score:
            print(f"\n❌ Score {avg_score:.0f} below minimum {args.min_score}", file=sys.stderr)
            return 1
        print(f"\n✅ Score {avg_score:.0f} meets minimum {args.min_score}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
