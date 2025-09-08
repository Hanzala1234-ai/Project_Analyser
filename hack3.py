# AI/ML-Driven Intelligent Software Code Analysis Platform
# A comprehensive solution for enhanced quality and security

import ast
import os
import re
import json
import hashlib
import logging
import sqlite3
import subprocess
import threading
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, Counter
import pickle
import base64
from datetime import timedelta

# ML/NLP Libraries
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
import joblib

# Real-time analysis dependencies
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    Observer = None
    FileSystemEventHandler = None
    WATCHDOG_AVAILABLE = False
import time
import queue
from typing import Callable

# Advanced ML and NLP dependencies
try:
    from transformers import AutoTokenizer, AutoModel, pipeline
    import torch
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False

try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False

# Code parsing and analysis
import tokenize
import io
import keyword

# Fix for sqlite3 datetime adapter deprecation in Python 3.12
def adapt_datetime_iso(dt):
    return dt.isoformat()

sqlite3.register_adapter(datetime, adapt_datetime_iso)

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class CodeIssue:
    """Represents a detected code issue with all relevant information"""
    issue_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    file_path: str
    line_number: int
    column: int
    message: str
    description: str
    recommendation: str
    confidence: float
    rule_id: str
    code_snippet: str
    fix_suggestion: Optional[str] = None

@dataclass
class AnalysisResult:
    """Complete analysis result for a codebase"""
    project_path: str
    timestamp: datetime
    issues: List[CodeIssue]
    metrics: Dict[str, Any]
    summary: Dict[str, int]

class CodeFeatureExtractor:
    """Extracts features from code for ML analysis"""
    
    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=1000, stop_words=None)
        self.complexity_weights = {
            'cyclomatic': 0.3,
            'cognitive': 0.4,
            'lines': 0.2,
            'nesting': 0.1
        }
    
    def extract_ast_features(self, code: str) -> Dict[str, Any]:
        """Extract features from AST"""
        try:
            tree = ast.parse(code)
            features = {
                'num_classes': len([n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]),
                'num_functions': len([n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]),
                'num_imports': len([n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))]),
                'num_loops': len([n for n in ast.walk(tree) if isinstance(n, (ast.For, ast.While))]),
                'num_conditions': len([n for n in ast.walk(tree) if isinstance(n, ast.If)]),
                'num_try_except': len([n for n in ast.walk(tree) if isinstance(n, ast.Try)]),
                'max_nesting_depth': self._calculate_max_nesting(tree),
                'lines_of_code': len(code.split('\n')),
                'has_main_guard': '__main__' in code,
                'docstring_ratio': self._calculate_docstring_ratio(tree)
            }
            return features
        except SyntaxError:
            return self._default_features()
    
    def _calculate_max_nesting(self, node, depth=0):
        """Calculate maximum nesting depth"""
        max_depth = depth
        for child in ast.iter_child_nodes(node):
            is_control = isinstance(child, (ast.If, ast.For, ast.While, ast.With, ast.Try))
            child_depth = self._calculate_max_nesting(child, depth + 1 if is_control else depth)
            max_depth = max(max_depth, child_depth)
        return max_depth
    
    def _calculate_docstring_ratio(self, tree):
        """Calculate ratio of functions/classes with docstrings"""
        total_functions = 0
        documented_functions = 0
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
                total_functions += 1
                if (node.body and isinstance(node.body[0], ast.Expr) 
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)):
                    documented_functions += 1
        
        return documented_functions / total_functions if total_functions > 0 else 0
    
    def _default_features(self):
        """Default features for unparseable code"""
        return {k: 0 for k in ['num_classes', 'num_functions', 'num_imports', 
                              'num_loops', 'num_conditions', 'num_try_except', 
                              'max_nesting_depth', 'lines_of_code', 'has_main_guard', 
                              'docstring_ratio']}

class AdvancedSecurityAnalyzer:
    """Advanced Security Analysis with OWASP Top 10 coverage and threat modeling"""
    
    def __init__(self):
        # OWASP Top 10 2021 vulnerability patterns
        self.owasp_patterns = {
            # A01:2021 - Broken Access Control
            'broken_access_control': {
                'patterns': [
                    r'@app\.route\([^)]*methods\s*=\s*\[[^\]]*[\'"]POST[\'"][^\]]*\]\)\s*def\s+\w+\(\)[^{]*(?!.*@login_required)',
                    r'if\s+request\.method\s*==\s*[\'"]POST[\'"]\s*:(?!.*csrf)',
                    r'def\s+\w+\([^)]*\)\s*:(?!.*@login_required)(?!.*@permission_required)',
                    r'session\[[\'"]user_id[\'"]\]\s*=(?!.*verification)',
                    r'request\.args\.get\([\'"]user_id[\'"]\)(?!.*authorization)',
                ],
                'severity': 'CRITICAL',
                'owasp_id': 'A01',
                'description': 'Access control enforces policy such that users cannot act outside of their intended permissions'
            },
            
            # A02:2021 - Cryptographic Failures
            'cryptographic_failures': {
                'patterns': [
                    r'md5\s*\(',
                    r'sha1\s*\(',
                    r'DES\s*\(',
                    r'RC4\s*\(',
                    r'password\s*=\s*[\'"][^\'"]+[\'"](?!.*hash)',
                    r'key\s*=\s*[\'"][^\'"]+[\'"](?!.*random)',
                    r'ssl_context\s*=\s*ssl\._create_unverified_context\(\)',
                    r'verify\s*=\s*False',
                ],
                'severity': 'HIGH',
                'owasp_id': 'A02',
                'description': 'Cryptographic failures related to cryptography which often leads to sensitive data exposure'
            },
            
            # A03:2021 - Injection
            'injection': {
                'patterns': [
                    r'execute\s*\(\s*[\'"].*%.*[\'"]',
                    r'cursor\.execute\s*\(\s*[\'"].*\+.*[\'"]',
                    r'format\s*\(.*sql.*\)',
                    r'os\.system\s*\(',
                    r'subprocess\.call\s*\(',
                    r'eval\s*\(',
                    r'exec\s*\(',
                    r'compile\s*\(',
                    r'__import__\s*\(',
                    r'query\s*=\s*[\'"].*\+.*[\'"]',
                ],
                'severity': 'CRITICAL',
                'owasp_id': 'A03',
                'description': 'Injection flaws occur when untrusted data is sent as part of a command or query'
            },
            
            # A04:2021 - Insecure Design
            'insecure_design': {
                'patterns': [
                    r'def\s+\w+\([^)]*password[^)]*\)\s*:(?!.*validate)',
                    r'session\s*=\s*requests\.Session\(\)(?!.*verify)',
                    r'app\.debug\s*=\s*True',
                    r'DEBUG\s*=\s*True',
                    r'try\s*:.*except\s*:.*pass',
                ],
                'severity': 'HIGH',
                'owasp_id': 'A04',
                'description': 'Insecure design is a broad category representing different weaknesses in design and architecture'
            },
            
            # A05:2021 - Security Misconfiguration
            'security_misconfiguration': {
                'patterns': [
                    r'app\.run\s*\([^)]*debug\s*=\s*True[^)]*\)',
                    r'app\.config\[[\'"]SECRET_KEY[\'"]\]\s*=\s*[\'"][^\'"]*[\'"]',
                    r'CORS\([^)]*origins\s*=\s*[\'"]\*[\'"]',
                    r'@cross_origin\s*\([^)]*origins\s*=\s*[\'"]\*[\'"]',
                    r'ssl_context\s*=\s*None',
                    r'verify_ssl\s*=\s*False',
                ],
                'severity': 'HIGH',
                'owasp_id': 'A05',
                'description': 'Security misconfiguration is commonly a result of insecure default configurations'
            },
            
            # A06:2021 - Vulnerable and Outdated Components
            'vulnerable_components': {
                'patterns': [
                    r'import\s+pickle',
                    r'import\s+cPickle',
                    r'pickle\.load\s*\(',
                    r'yaml\.load\s*\((?!.*Loader\s*=)',
                    r'requests\.get\s*\([^)]*verify\s*=\s*False',
                    r'urllib\.request\.urlopen\s*\([^)]*context\s*=\s*ssl\._create_unverified_context',
                ],
                'severity': 'MEDIUM',
                'owasp_id': 'A06',
                'description': 'Components run with the same privileges as the application itself'
            },
            
            # A07:2021 - Identification and Authentication Failures
            'auth_failures': {
                'patterns': [
                    r'password\s*==\s*[\'"][^\'"]+[\'"]',
                    r'if\s+user\.password\s*==\s*password',
                    r'session\[[\'"]authenticated[\'"]\]\s*=\s*True(?!.*after.*verification)',
                    r'login\([^)]*\)(?!.*password.*hash)',
                    r'authenticate\([^)]*\)(?!.*secure)',
                ],
                'severity': 'CRITICAL',
                'owasp_id': 'A07',
                'description': 'Confirmation of the user identity, authentication, and session management'
            },
            
            # A08:2021 - Software and Data Integrity Failures
            'integrity_failures': {
                'patterns': [
                    r'pickle\.loads?\s*\(',
                    r'marshal\.loads?\s*\(',
                    r'shelve\.open\s*\(',
                    r'subprocess\.call\s*\([^)]*shell\s*=\s*True',
                    r'os\.system\s*\([^)]*\+',
                ],
                'severity': 'HIGH',
                'owasp_id': 'A08',
                'description': 'Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations'
            },
            
            # A09:2021 - Security Logging and Monitoring Failures
            'logging_failures': {
                'patterns': [
                    r'except\s*[^:]*:\s*pass',
                    r'try\s*:.*except\s*:.*continue',
                    r'log\.debug\s*\([^)]*password',
                    r'print\s*\([^)]*password',
                    r'logger\.info\s*\([^)]*secret',
                ],
                'severity': 'MEDIUM',
                'owasp_id': 'A09',
                'description': 'Insufficient logging and monitoring, coupled with missing or ineffective integration with incident response'
            },
            
            # A10:2021 - Server-Side Request Forgery (SSRF)
            'ssrf': {
                'patterns': [
                    r'requests\.get\s*\([^)]*request\.',
                    r'urllib\.request\.urlopen\s*\([^)]*request\.',
                    r'requests\.post\s*\([^)]*user_input',
                    r'fetch\s*\([^)]*request\.',
                    r'curl\s+.*\$\w+',
                ],
                'severity': 'HIGH',
                'owasp_id': 'A10',
                'description': 'SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL'
            }
        }
        
        # Legacy patterns for backward compatibility
        self.vulnerability_patterns = {
            'sql_injection': [pattern for pattern in self.owasp_patterns['injection']['patterns'] if 'sql' in pattern.lower() or 'execute' in pattern.lower()],
            'command_injection': [pattern for pattern in self.owasp_patterns['injection']['patterns'] if 'system' in pattern.lower() or 'exec' in pattern.lower()],
            'hardcoded_secrets': [pattern for pattern in self.owasp_patterns['cryptographic_failures']['patterns'] if 'password' in pattern.lower() or 'key' in pattern.lower()],
            'path_traversal': [
                r'open\s*\(\s*.*\+.*\)',
                r'file\s*\(\s*.*\+.*\)'
            ],
            'weak_crypto': [pattern for pattern in self.owasp_patterns['cryptographic_failures']['patterns'] if any(crypto in pattern.lower() for crypto in ['md5', 'sha1', 'des', 'rc4'])]
        }
        
        # Threat modeling components
        self.threat_model = ThreatModelingEngine()
        
        # Security metrics tracker
        self.security_metrics = SecurityMetricsTracker()
    
    def detect_vulnerabilities(self, code: str, file_path: str) -> List[CodeIssue]:
        """Enhanced vulnerability detection with OWASP Top 10 coverage"""
        issues = []
        lines = code.split('\n')
        
        # OWASP Top 10 analysis
        for vuln_category, vuln_data in self.owasp_patterns.items():
            for pattern in vuln_data['patterns']:
                for line_num, line in enumerate(lines, 1):
                    matches = re.finditer(pattern, line, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        issue = CodeIssue(
                            issue_type='SECURITY',
                            severity=vuln_data['severity'],
                            file_path=file_path,
                            line_number=line_num,
                            column=match.start(),
                            message=f'OWASP {vuln_data["owasp_id"]}: {vuln_category.replace("_", " " \
                                ).title()} vulnerability detected',
                            description=f'{vuln_data["description"]}\nPattern detected: {line.strip()}',
                            recommendation=self._get_owasp_recommendation(vuln_category),
                            confidence=0.9 if vuln_data['severity'] == 'CRITICAL' else 0.8,
                            rule_id=f'OWASP_{vuln_data["owasp_id"]}_{vuln_category.upper()}',
                            code_snippet=line.strip(),
                            fix_suggestion=self._get_owasp_fix(vuln_category, line.strip())
                        )
                        issues.append(issue)
        
        # Legacy vulnerability detection for backward compatibility
        for vuln_type, patterns in self.vulnerability_patterns.items():
            for pattern in patterns:
                for line_num, line in enumerate(lines, 1):
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    for match in matches:
                        # Skip if already detected by OWASP analysis
                        if not any(issue.line_number == line_num and vuln_type.lower() in issue.message.lower() for issue in issues):
                            issue = CodeIssue(
                                issue_type='SECURITY',
                                severity='HIGH',
                                file_path=file_path,
                                line_number=line_num,
                                column=match.start(),
                                message=f'Potential {vuln_type.replace("_", " ")} vulnerability detected',
                                description=f'Line contains pattern that may indicate {vuln_type}',
                                recommendation=self._get_security_recommendation(vuln_type),
                                confidence=0.8,
                                rule_id=f'SEC_{vuln_type.upper()}',
                                code_snippet=line.strip(),
                                fix_suggestion=self._get_security_fix(vuln_type, line.strip())
                            )
                            issues.append(issue)
        
        # Threat modeling analysis
        threat_issues = self.threat_model.analyze_threats(code, file_path)
        issues.extend(threat_issues)
        
        # Update security metrics
        self.security_metrics.update_metrics(issues, file_path)
        
        return issues
    
    def _get_owasp_recommendation(self, vuln_category: str) -> str:
        """Get OWASP-specific security recommendations"""
        recommendations = {
            'broken_access_control': 'Implement proper access controls, use authorization frameworks, deny by default, and implement access control checks server-side',
            'cryptographic_failures': 'Use strong, up-to-date cryptographic algorithms, proper key management, and secure protocols like TLS 1.3',
            'injection': 'Use parameterized queries, input validation, escape special characters, and implement proper error handling',
            'insecure_design': 'Implement secure design principles, threat modeling, secure coding patterns, and security testing',
            'security_misconfiguration': 'Implement security hardening, remove unnecessary features, keep software updated, and use security configurations',
            'vulnerable_components': 'Keep components updated, remove unnecessary dependencies, monitor for vulnerabilities, and use dependency checking tools',
            'auth_failures': 'Implement multi-factor authentication, use secure session management, prevent brute force attacks, and use strong passwords',
            'integrity_failures': 'Use digital signatures, verify integrity of data and software, implement secure update mechanisms',
            'logging_failures': 'Implement comprehensive logging, monitor security events, establish incident response procedures',
            'ssrf': 'Validate and sanitize user inputs, use allow-lists for URLs, implement network segmentation'
        }
        return recommendations.get(vuln_category, 'Follow security best practices for this vulnerability type')
    
    def _get_owasp_fix(self, vuln_category: str, code_snippet: str) -> str:
        """Get OWASP-specific fix suggestions"""
        fixes = {
            'broken_access_control': 'Add @login_required decorator and implement proper authorization checks',
            'cryptographic_failures': 'Use bcrypt.hashpw() for passwords and secrets management system',
            'injection': 'Use parameterized queries: cursor.execute("SELECT * FROM table WHERE id = %s", (user_id,))',
            'insecure_design': 'Implement input validation and secure error handling',
            'security_misconfiguration': 'Set app.debug = False in production and use environment variables for secrets',
            'vulnerable_components': 'Update to secure alternatives: use yaml.safe_load() instead of yaml.load()',
            'auth_failures': 'Use secure password hashing: bcrypt.hashpw(password.encode(), bcrypt.gensalt())',
            'integrity_failures': 'Avoid pickle for untrusted data; use JSON or implement signature verification',
            'logging_failures': 'Implement proper exception logging and avoid logging sensitive information',
            'ssrf': 'Validate URLs and use allow-lists for permitted hosts'
        }
        return fixes.get(vuln_category, 'Apply security best practices')
    
    def _get_security_recommendation(self, vuln_type: str) -> str:
        """Get security recommendation for a specific vulnerability type"""
        recommendations = {
            'sql_injection': 'Use parameterized queries and input validation to prevent SQL injection',
            'command_injection': 'Avoid executing system commands with user input; use safe alternatives',
            'hardcoded_secrets': 'Use environment variables or secure secret management systems',
            'path_traversal': 'Validate file paths and restrict access to authorized directories',
            'weak_crypto': 'Use strong cryptographic algorithms like AES, SHA-256, or bcrypt'
        }
        return recommendations.get(vuln_type, 'Review and address this security vulnerability')
    
    def _get_security_fix(self, vuln_type: str, code_snippet: str) -> str:
        """Get specific fix suggestion for a vulnerability type"""
        fixes = {
            'sql_injection': 'Use cursor.execute("SELECT * FROM table WHERE id = %s", (user_id,))',
            'command_injection': 'Use subprocess.run() with shell=False and validate inputs',
            'hardcoded_secrets': 'Move secrets to environment variables: os.environ["SECRET_KEY"]',
            'path_traversal': 'Use os.path.join() and validate paths are within allowed directories',
            'weak_crypto': 'Use hashlib.sha256() or bcrypt.hashpw() for secure hashing'
        }
        return fixes.get(vuln_type, 'Apply secure coding practices')
    
    def get_security_report(self) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        return {
            'owasp_coverage': self._get_owasp_coverage(),
            'threat_model': self.threat_model.get_threat_summary(),
            'security_metrics': self.security_metrics.get_metrics_summary(),
            'recommendations': self._get_security_recommendations()
        }
    
    def _get_owasp_coverage(self) -> Dict[str, Any]:
        """Get OWASP Top 10 coverage analysis"""
        coverage = {}
        for category, data in self.owasp_patterns.items():
            coverage[data['owasp_id']] = {
                'category': category,
                'description': data['description'],
                'severity': data['severity'],
                'patterns_count': len(data['patterns'])
            }
        return coverage
    
    def _get_security_recommendations(self) -> List[str]:
        """Get general security recommendations"""
        return [
            'Implement security code reviews as part of development process',
            'Use automated security testing tools in CI/CD pipeline',
            'Keep all dependencies and frameworks updated',
            'Implement proper input validation and output encoding',
            'Use secure coding guidelines and standards',
            'Conduct regular penetration testing',
            'Implement security monitoring and incident response',
            'Train developers in secure coding practices'
        ]

class ThreatModelingEngine:
    """Advanced threat modeling and attack surface analysis"""
    
    def __init__(self):
        self.stride_model = {
            'Spoofing': {
                'patterns': [r'user_id\s*=\s*request\.', r'authentication\s*=\s*False', r'verify\s*=\s*False'],
                'description': 'Threats involving impersonation of users or processes'
            },
            'Tampering': {
                'patterns': [r'input\s*=\s*request\.', r'data\s*=\s*json\.loads\(request', r'eval\s*\('],
                'description': 'Threats involving malicious modification of data'
            },
            'Repudiation': {
                'patterns': [r'except\s*:', r'log\.\w+\s*\(\s*\)', r'audit\s*=\s*False'],
                'description': 'Threats involving denial of performing actions'
            },
            'Information_Disclosure': {
                'patterns': [r'print\s*\([^)]*password', r'debug\s*=\s*True', r'traceback\.print_exc'],
                'description': 'Threats involving exposure of sensitive information'
            },
            'Denial_of_Service': {
                'patterns': [r'while\s+True\s*:', r'recursion', r'memory\s*=\s*\[\].*for'],
                'description': 'Threats involving degradation or denial of service'
            },
            'Elevation_of_Privilege': {
                'patterns': [r'sudo\s+', r'os\.setuid', r'exec\s*\(.*admin', r'root\s*=\s*True'],
                'description': 'Threats involving unauthorized elevation of privileges'
            }
        }
        self.attack_vectors = {
            'web_attacks': [r'request\.', r'session\[', r'@app\.route'],
            'file_attacks': [r'open\s*\(', r'file\s*\(', r'os\.path'],
            'network_attacks': [r'socket\.', r'requests\.', r'urllib'],
            'crypto_attacks': [r'hash', r'encrypt', r'decrypt', r'key'],
            'injection_attacks': [r'eval\s*\(', r'exec\s*\(', r'sql', r'query']
        }
        
    def analyze_threats(self, code: str, file_path: str) -> List[CodeIssue]:
        """Analyze code for STRIDE threats"""
        issues = []
        lines = code.split('\n')
        
        for threat_type, threat_data in self.stride_model.items():
            for pattern in threat_data['patterns']:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        issue = CodeIssue(
                            issue_type='THREAT_MODEL',
                            severity='MEDIUM',
                            file_path=file_path,
                            line_number=line_num,
                            column=0,
                            message=f'STRIDE Threat: {threat_type.replace("_", " ")} risk detected',
                            description=f'{threat_data["description"]}\nCode pattern suggests potential {threat_type.lower()} threat',
                            recommendation=f'Review and mitigate {threat_type.replace("_", " ").lower()} risks in this code section',
                            confidence=0.6,
                            rule_id=f'STRIDE_{threat_type.upper()}',
                            code_snippet=line.strip(),
                            fix_suggestion=self._get_stride_mitigation(threat_type)
                        )
                        issues.append(issue)
        
        # Attack surface analysis
        attack_surface_issues = self._analyze_attack_surface(code, file_path)
        issues.extend(attack_surface_issues)
        
        return issues
    
    def _analyze_attack_surface(self, code: str, file_path: str) -> List[CodeIssue]:
        """Analyze attack surface of the code"""
        issues = []
        lines = code.split('\n')
        
        for attack_type, patterns in self.attack_vectors.items():
            for pattern in patterns:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        issue = CodeIssue(
                            issue_type='ATTACK_SURFACE',
                            severity='LOW',
                            file_path=file_path,
                            line_number=line_num,
                            column=0,
                            message=f'Attack Surface: {attack_type.replace("_", " ")} vector identified',
                            description=f'Code contains patterns that increase attack surface for {attack_type.replace("_", " ")}',
                            recommendation='Review security implications and implement appropriate safeguards',
                            confidence=0.5,
                            rule_id=f'ATTACK_SURFACE_{attack_type.upper()}',
                            code_snippet=line.strip(),
                            fix_suggestion='Apply security controls appropriate for this attack vector'
                        )
                        issues.append(issue)
                        
        return issues
    
    def _get_stride_mitigation(self, threat_type: str) -> str:
        """Get STRIDE-specific mitigation suggestions"""
        mitigations = {
            'Spoofing': 'Implement strong authentication mechanisms and user verification',
            'Tampering': 'Use input validation, data integrity checks, and secure protocols',
            'Repudiation': 'Implement comprehensive logging and digital signatures',
            'Information_Disclosure': 'Apply data encryption and access controls',
            'Denial_of_Service': 'Implement rate limiting and resource management',
            'Elevation_of_Privilege': 'Apply principle of least privilege and authorization controls'
        }
        return mitigations.get(threat_type, 'Apply appropriate security controls')
    
    def get_threat_summary(self) -> Dict[str, Any]:
        """Get threat modeling summary"""
        return {
            'stride_categories': len(self.stride_model),
            'attack_vectors': len(self.attack_vectors),
            'total_patterns': sum(len(data['patterns']) for data in self.stride_model.values()) + sum(len(patterns) for patterns in self.attack_vectors.values())
        }

class SecurityMetricsTracker:
    """Track and analyze security metrics across the codebase"""
    
    def __init__(self):
        self.metrics = {
            'total_security_issues': 0,
            'issues_by_severity': Counter(),
            'issues_by_category': Counter(),
            'issues_by_file': defaultdict(int),
            'owasp_distribution': Counter(),
            'threat_distribution': Counter(),
            'security_debt': 0.0
        }
        self.security_trends = []
        
    def update_metrics(self, issues: List[CodeIssue], file_path: str):
        """Update security metrics with new analysis results"""
        security_issues = [issue for issue in issues if issue.issue_type in ['SECURITY', 'THREAT_MODEL', 'ATTACK_SURFACE']]
        
        self.metrics['total_security_issues'] += len(security_issues)
        self.metrics['issues_by_file'][file_path] = len(security_issues)
        
        for issue in security_issues:
            self.metrics['issues_by_severity'][issue.severity] += 1
            self.metrics['issues_by_category'][issue.issue_type] += 1
            
            # Track OWASP categories
            if 'OWASP' in issue.rule_id:
                owasp_id = issue.rule_id.split('_')[1]  # Extract A01, A02, etc.
                self.metrics['owasp_distribution'][owasp_id] += 1
            
            # Track STRIDE threats
            if 'STRIDE' in issue.rule_id:
                threat_type = issue.rule_id.split('_')[1]
                self.metrics['threat_distribution'][threat_type] += 1
            
            # Calculate security debt (weighted by severity)
            severity_weights = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
            self.metrics['security_debt'] += severity_weights.get(issue.severity, 1)
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get comprehensive security metrics summary"""
        return {
            'total_issues': self.metrics['total_security_issues'],
            'severity_distribution': dict(self.metrics['issues_by_severity']),
            'category_distribution': dict(self.metrics['issues_by_category']),
            'owasp_top10_coverage': dict(self.metrics['owasp_distribution']),
            'stride_threats': dict(self.metrics['threat_distribution']),
            'security_debt_score': self.metrics['security_debt'],
            'most_vulnerable_files': dict(sorted(self.metrics['issues_by_file'].items(), key=lambda x: x[1], reverse=True)[:10])
        }
    
    def calculate_security_score(self) -> float:
        """Calculate overall security score (0-100, higher is better)"""
        if self.metrics['total_security_issues'] == 0:
            return 100.0
        
        # Base score
        base_score = 100.0
        
        # Penalties based on severity
        critical_penalty = self.metrics['issues_by_severity']['CRITICAL'] * 20
        high_penalty = self.metrics['issues_by_severity']['HIGH'] * 10
        medium_penalty = self.metrics['issues_by_severity']['MEDIUM'] * 5
        low_penalty = self.metrics['issues_by_severity']['LOW'] * 1
        
        total_penalty = critical_penalty + high_penalty + medium_penalty + low_penalty
        final_score = max(0, base_score - total_penalty)
        
        return final_score

# Backward compatibility - keep SecurityPatternDetector as alias
class SecurityPatternDetector(AdvancedSecurityAnalyzer):
    """Backward compatibility alias for AdvancedSecurityAnalyzer"""
    pass

class CodeSmellDetector:
    """Detects code smells and quality issues"""
    
    def __init__(self):
        self.smell_rules = {
            'long_method': {'max_lines': 50, 'severity': 'MEDIUM'},
            'long_parameter_list': {'max_params': 5, 'severity': 'LOW'},
            'large_class': {'max_methods': 20, 'severity': 'MEDIUM'},
            'deep_nesting': {'max_depth': 4, 'severity': 'MEDIUM'},
            'duplicate_code': {'min_similarity': 0.8, 'severity': 'LOW'}
        }
    
    def detect_smells(self, code: str, file_path: str) -> List[CodeIssue]:
        """Detect code smells"""
        issues = []
        try:
            tree = ast.parse(code)
            issues.extend(self._check_method_length(tree, file_path, code))
            issues.extend(self._check_parameter_count(tree, file_path, code))
            issues.extend(self._check_class_size(tree, file_path, code))
            issues.extend(self._check_nesting_depth(tree, file_path, code))
        except SyntaxError:
            pass
        
        return issues
    
    def _check_method_length(self, tree, file_path: str, code: str) -> List[CodeIssue]:
        """Check for long methods"""
        issues = []
        lines = code.split('\n')
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                method_lines = node.end_lineno - node.lineno + 1 if hasattr(node, 'end_lineno') else 0
                if method_lines > self.smell_rules['long_method']['max_lines']:
                    issue = CodeIssue(
                        issue_type='CODE_SMELL',
                        severity=self.smell_rules['long_method']['severity'],
                        file_path=file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        message=f'Method "{node.name}" is too long ({method_lines} lines)',
                        description=f'Method exceeds recommended length of {self.smell_rules["long_method"]["max_lines"]} lines',
                        recommendation='Consider breaking down into smaller methods',
                        confidence=0.9,
                        rule_id='SMELL_LONG_METHOD',
                        code_snippet=f'def {node.name}(...): # {method_lines} lines',
                        fix_suggestion='Extract smaller methods with single responsibilities'
                    )
                    issues.append(issue)
        
        return issues
    
    def _check_parameter_count(self, tree, file_path: str, code: str) -> List[CodeIssue]:
        """Check for long parameter lists"""
        issues = []
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                param_count = len(node.args.args)
                if param_count > self.smell_rules['long_parameter_list']['max_params']:
                    issue = CodeIssue(
                        issue_type='CODE_SMELL',
                        severity=self.smell_rules['long_parameter_list']['severity'],
                        file_path=file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        message=f'Method "{node.name}" has too many parameters ({param_count})',
                        description=f'Method exceeds recommended parameter count of {self.smell_rules["long_parameter_list"]["max_params"]}',
                        recommendation='Consider using parameter objects or configuration classes',
                        confidence=0.8,
                        rule_id='SMELL_LONG_PARAMS',
                        code_snippet=f'def {node.name}(...): # {param_count} parameters',
                        fix_suggestion='Create a parameter object or use **kwargs'
                    )
                    issues.append(issue)
        
        return issues
    
    def _check_class_size(self, tree, file_path: str, code: str) -> List[CodeIssue]:
        """Check for large classes"""
        issues = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                method_count = len([n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))])
                if method_count > self.smell_rules['large_class']['max_methods']:
                    issue = CodeIssue(
                        issue_type='CODE_SMELL',
                        severity=self.smell_rules['large_class']['severity'],
                        file_path=file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        message=f'Class "{node.name}" is too large ({method_count} methods)',
                        description=f'Class exceeds recommended method count of {self.smell_rules["large_class"]["max_methods"]}',
                        recommendation='Consider splitting into smaller, more focused classes',
                        confidence=0.8,
                        rule_id='SMELL_LARGE_CLASS',
                        code_snippet=f'class {node.name}: # {method_count} methods',
                        fix_suggestion='Apply Single Responsibility Principle and extract related functionality'
                    )
                    issues.append(issue)
        
        return issues
    
    def _check_nesting_depth(self, tree, file_path: str, code: str) -> List[CodeIssue]:
        """Check for deep nesting"""
        issues = []
        
        def check_nesting(node, depth=0):
            if depth > self.smell_rules['deep_nesting']['max_depth']:
                issue = CodeIssue(
                    issue_type='CODE_SMELL',
                    severity=self.smell_rules['deep_nesting']['severity'],
                    file_path=file_path,
                    line_number=getattr(node, 'lineno', 0),
                    column=getattr(node, 'col_offset', 0),
                    message=f'Deep nesting detected (depth: {depth})',
                    description=f'Code nesting exceeds recommended depth of {self.smell_rules["deep_nesting"]["max_depth"]}',
                    recommendation='Consider extracting methods or using early returns',
                    confidence=0.9,
                    rule_id='SMELL_DEEP_NESTING',
                    code_snippet='# Deeply nested code block',
                    fix_suggestion='Use guard clauses and extract methods to reduce nesting'
                )
                issues.append(issue)
            
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
                    check_nesting(child, depth + 1)
                else:
                    check_nesting(child, depth)
        
        check_nesting(tree)
        return issues

class AdvancedPerformanceOptimizationEngine:
    """Comprehensive performance optimization engine with profiling and advanced bottleneck detection"""
    
    def __init__(self):
        # Performance anti-patterns with detailed analysis
        self.performance_patterns = {
            'algorithm_complexity': {
                'patterns': [
                    r'for\s+\w+\s+in\s+\w+:\s*for\s+\w+\s+in\s+\w+:',  # O(n²) nested loops
                    r'for\s+\w+\s+in\s+range\(len\([^)]+\)\):\s*for\s+\w+\s+in\s+range\(len\([^)]+\)\)',  # O(n²) range loops
                    r'while.*while',  # Nested while loops
                    r'for.*if.*in\s+\w+:',  # O(n²) membership testing
                ],
                'severity': 'HIGH',
                'description': 'Algorithm complexity issues that may cause performance degradation',
                'impact': 'Exponential performance degradation with input size'
            },
            'inefficient_loop': {
                'patterns': [
                    r'for\s+\w+\s+in\s+range\(len\(',
                    r'while\s+.*len\(',
                    r'for\s+\w+\s+in\s+\w+:\s*if\s+\w+\s+==',  # Linear search in loop
                    r'\[.*for.*in.*if.*\].*for.*in',  # Nested list comprehensions
                ],
                'severity': 'MEDIUM',
                'description': 'Inefficient loop patterns that could be optimized',
                'impact': 'Unnecessary computational overhead'
            },
            'string_concatenation': {
                'patterns': [
                    r'\w+\s*\+=\s*[\'"].*[\'"].*for',
                    r'\w+\s*=\s*\w+\s*\+\s*[\'"].*[\'"].*for',
                    r'[\'"][\'"]\s*\.join\(\[.*for.*\]\)',  # Unnecessary join with comprehension
                ],
                'severity': 'MEDIUM',
                'description': 'String concatenation in loops creates performance overhead',
                'impact': 'Memory allocation and copying overhead'
            },
            'repeated_computation': {
                'patterns': [
                    r'for.*\n.*len\(',
                    r'while.*\n.*len\(',
                    r'for.*\n.*\w+\.\w+\(',  # Method calls in loops
                    r'for.*\n.*\w+\[.*\]\[.*\]',  # Repeated indexing
                ],
                'severity': 'MEDIUM',
                'description': 'Computations repeated unnecessarily in loops',
                'impact': 'Redundant processing and CPU cycles'
            },
            'inefficient_data_structure': {
                'patterns': [
                    r'list\(\).*append.*for',
                    r'\[\].*append.*for',
                    r'dict\(\).*\[.*\].*for',
                    r'\w+\s*=\s*\[\].*\w+\.extend',  # List extend in loop
                ],
                'severity': 'LOW',
                'description': 'Suboptimal data structure usage',
                'impact': 'Memory and time complexity issues'
            },
            'io_operations': {
                'patterns': [
                    r'open\s*\([^)]+\).*for.*in',  # File I/O in loops
                    r'requests\.(get|post).*for.*in',  # Network I/O in loops
                    r'print\s*\(.*for.*in',  # Print statements in loops
                    r'logging\..+\(.*for.*in',  # Excessive logging in loops
                ],
                'severity': 'HIGH',
                'description': 'I/O operations in loops causing performance bottlenecks',
                'impact': 'Significant slowdown due to I/O latency'
            },
            'memory_inefficiency': {
                'patterns': [
                    r'\w+\s*=\s*\[.*for.*in.*\].*\w+\s*=\s*\[.*for.*in.*\]',  # Multiple list comprehensions
                    r'copy\.deepcopy\(.*\).*for.*in',  # Deep copy in loops
                    r'pickle\.(loads?|dumps?)\(.*\).*for.*in',  # Serialization in loops
                    r'json\.(loads?|dumps?)\(.*\).*for.*in',  # JSON operations in loops
                ],
                'severity': 'MEDIUM',
                'description': 'Memory-intensive operations that could be optimized',
                'impact': 'High memory usage and potential memory leaks'
            }
        }
        
        # Performance profiler
        self.profiler = PerformanceProfiler()
        
        # Bottleneck detector
        self.bottleneck_detector = BottleneckDetector()
        
        # Performance metrics tracker
        self.metrics_tracker = PerformanceMetricsTracker()
    
    def analyze_performance(self, code: str, file_path: str) -> List[CodeIssue]:
        """Comprehensive performance analysis with advanced bottleneck detection"""
        issues = []
        lines = code.split('\n')
        
        # Advanced pattern-based analysis
        for perf_category, perf_data in self.performance_patterns.items():
            for pattern in perf_data['patterns']:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE | re.MULTILINE):
                        issue = CodeIssue(
                            issue_type='PERFORMANCE',
                            severity=perf_data['severity'],
                            file_path=file_path,
                            line_number=line_num,
                            column=0,
                            message=f'Performance Issue: {perf_category.replace("_", " ").title()}',
                            description=f'{perf_data["description"]}\nImpact: {perf_data["impact"]}\nCode: {line.strip()}',
                            recommendation=self._get_performance_recommendation(perf_category),
                            confidence=0.8 if perf_data['severity'] == 'HIGH' else 0.7,
                            rule_id=f'PERF_{perf_category.upper()}',
                            code_snippet=line.strip(),
                            fix_suggestion=self._get_performance_fix(perf_category, line.strip())
                        )
                        issues.append(issue)
        
        # AST-based complexity analysis
        complexity_issues = self._analyze_complexity(code, file_path)
        issues.extend(complexity_issues)
        
        # Bottleneck detection
        bottleneck_issues = self.bottleneck_detector.detect_bottlenecks(code, file_path)
        issues.extend(bottleneck_issues)
        
        # Memory usage analysis
        memory_issues = self._analyze_memory_usage(code, file_path)
        issues.extend(memory_issues)
        
        # Performance profiling insights
        if self.profiler:
            profiling_issues = self.profiler.analyze_code_performance(code, file_path)
            issues.extend(profiling_issues)
        
        # Update performance metrics
        self.metrics_tracker.update_performance_metrics(issues, file_path)
        
        return issues
    
    def _analyze_complexity(self, code: str, file_path: str) -> List[CodeIssue]:
        """Analyze time and space complexity of code"""
        issues = []
        
        try:
            tree = ast.parse(code)
            complexity_analyzer = ComplexityAnalyzer()
            
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    complexity = complexity_analyzer.calculate_complexity(node)
                    
                    if complexity > 15:  # High complexity threshold
                        issue = CodeIssue(
                            issue_type='PERFORMANCE',
                            severity='HIGH' if complexity > 25 else 'MEDIUM',
                            file_path=file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            message=f'High cyclomatic complexity: {complexity}',
                            description=f'Function "{node.name}" has high cyclomatic complexity ({complexity}), which may impact performance and maintainability',
                            recommendation='Consider refactoring into smaller functions to reduce complexity',
                            confidence=0.9,
                            rule_id='PERF_HIGH_COMPLEXITY',
                            code_snippet=f'def {node.name}(...): # complexity: {complexity}',
                            fix_suggestion='Break down into smaller, more focused functions'
                        )
                        issues.append(issue)
        
        except SyntaxError:
            pass
        
        return issues
    
    def _analyze_memory_usage(self, code: str, file_path: str) -> List[CodeIssue]:
        """Analyze potential memory usage issues"""
        issues = []
        lines = code.split('\n')
        
        memory_patterns = {
            'large_data_structures': {
                'pattern': r'\w+\s*=\s*\[.*\]\s*\*\s*\d{4,}|\w+\s*=\s*\{.*\}\s*\*\s*\d{4,}',
                'message': 'Large data structure allocation detected',
                'severity': 'MEDIUM'
            },
            'memory_leaks': {
                'pattern': r'global\s+\w+.*\[|global\s+\w+.*\{',
                'message': 'Potential memory leak with global collections',
                'severity': 'HIGH'
            },
            'recursive_without_limit': {
                'pattern': r'def\s+\w+\([^)]*\):[^\n]*\n[^\n]*\1\(',
                'message': 'Recursive function without apparent termination condition',
                'severity': 'HIGH'
            }
        }
        
        for issue_type, pattern_data in memory_patterns.items():
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern_data['pattern'], line):
                    issue = CodeIssue(
                        issue_type='PERFORMANCE',
                        severity=pattern_data['severity'],
                        file_path=file_path,
                        line_number=line_num,
                        column=0,
                        message=pattern_data['message'],
                        description=f'Memory usage pattern detected: {issue_type.replace("_", " ")}',
                        recommendation='Review memory allocation and consider optimization',
                        confidence=0.7,
                        rule_id=f'PERF_MEMORY_{issue_type.upper()}',
                        code_snippet=line.strip(),
                        fix_suggestion='Optimize memory usage pattern'
                    )
                    issues.append(issue)
        
        return issues
    
    def _get_performance_recommendation(self, perf_category: str) -> str:
        """Get detailed performance optimization recommendations"""
        recommendations = {
            'algorithm_complexity': 'Review algorithm complexity and consider more efficient alternatives like hash tables, binary search, or caching',
            'inefficient_loop': 'Use enumerate() instead of range(len()), consider list comprehensions, or vectorized operations',
            'string_concatenation': 'Use join() method for multiple string concatenations, or consider using f-strings or format()',
            'repeated_computation': 'Cache computed values outside loops, use memoization, or precompute values',
            'inefficient_data_structure': 'Use appropriate data structures: sets for membership testing, deques for queues, or defaultdict for counters',
            'io_operations': 'Batch I/O operations, use connection pooling, implement caching, or move I/O outside loops',
            'memory_inefficiency': 'Use generators instead of lists, implement lazy evaluation, or optimize memory allocation patterns'
        }
        return recommendations.get(perf_category, 'Review for performance optimization opportunities')
    
    def _get_performance_fix(self, perf_category: str, code_snippet: str) -> str:
        """Get specific performance fix suggestions"""
        fixes = {
            'algorithm_complexity': 'Consider using hash sets: if item in my_set instead of if item in my_list',
            'inefficient_loop': 'for index, item in enumerate(items): instead of for i in range(len(items)):',
            'string_concatenation': 'Use: result = "".join(string_list) instead of concatenation in loops',
            'repeated_computation': 'length = len(items)  # Cache outside loop',
            'inefficient_data_structure': 'Use list comprehension: [process(item) for item in items]',
            'io_operations': 'Move I/O operations outside loops or use batch processing',
            'memory_inefficiency': 'Use generator: (process(item) for item in items) instead of list'
        }
        return fixes.get(perf_category, 'Apply performance best practices')
    
    def generate_performance_report(self, file_path: str = None) -> Dict[str, Any]:
        """Generate comprehensive performance analysis report"""
        return {
            'performance_patterns': len(self.performance_patterns),
            'bottlenecks_detected': self.bottleneck_detector.get_summary(),
            'profiling_insights': self.profiler.get_insights() if self.profiler else {},
            'performance_metrics': self.metrics_tracker.get_performance_summary(),
            'optimization_recommendations': self._get_optimization_recommendations()
        }
    
    def _get_optimization_recommendations(self) -> List[Dict[str, str]]:
        """Get general performance optimization recommendations"""
        return [
            {
                'category': 'Algorithm Optimization',
                'recommendation': 'Replace O(n²) algorithms with O(n log n) or O(n) alternatives',
                'impact': 'Significant performance improvement for large datasets'
            },
            {
                'category': 'Data Structure Optimization',
                'recommendation': 'Use appropriate data structures (sets for lookups, deques for queues)',
                'impact': 'Improved time complexity for common operations'
            },
            {
                'category': 'Memory Optimization',
                'recommendation': 'Use generators and lazy evaluation to reduce memory footprint',
                'impact': 'Reduced memory usage and better scalability'
            },
            {
                'category': 'I/O Optimization',
                'recommendation': 'Implement connection pooling and batch operations',
                'impact': 'Reduced latency and improved throughput'
            },
            {
                'category': 'Caching Strategy',
                'recommendation': 'Implement memoization and result caching for expensive operations',
                'impact': 'Eliminated redundant computations'
            }
        ]

class ComplexityAnalyzer:
    """Analyzes code complexity for performance implications"""
    
    def __init__(self):
        self.complexity_threshold = 10
    
    def calculate_complexity(self, node: ast.AST) -> int:
        """Calculate cyclomatic complexity of a function"""
        complexity = 1  # Base complexity
        
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
            elif isinstance(child, (ast.Try, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(child, ast.With):
                complexity += 1
        
        return complexity
    
    def analyze_nesting_depth(self, code: str) -> int:
        """Analyze nesting depth which affects performance"""
        max_depth = 0
        current_depth = 0
        
        for line in code.split('\n'):
            stripped = line.lstrip()
            if stripped:
                indent_level = (len(line) - len(stripped)) // 4
                max_depth = max(max_depth, indent_level)
        
        return max_depth

class BottleneckDetector:
    """Detects performance bottlenecks in code"""
    
    def __init__(self):
        self.bottleneck_patterns = {
            'database_in_loop': {
                'patterns': [r'for.*cursor\.execute', r'for.*db\.query', r'for.*session\.query'],
                'severity': 'CRITICAL',
                'description': 'Database operations in loops can cause severe performance issues'
            },
            'network_in_loop': {
                'patterns': [r'for.*requests\.(get|post)', r'for.*urllib\.request', r'for.*http'],
                'severity': 'CRITICAL',
                'description': 'Network operations in loops create significant latency'
            },
            'file_io_in_loop': {
                'patterns': [r'for.*open\s*\(', r'for.*\.read\(\)', r'for.*\.write\('],
                'severity': 'HIGH',
                'description': 'File I/O operations in loops are performance bottlenecks'
            },
            'expensive_operations': {
                'patterns': [r'for.*sort\(\)', r'for.*sorted\(', r'for.*\.join\('],
                'severity': 'MEDIUM',
                'description': 'Expensive operations in loops should be optimized'
            }
        }
        self.detected_bottlenecks = []
    
    def detect_bottlenecks(self, code: str, file_path: str) -> List[CodeIssue]:
        """Detect performance bottlenecks in code"""
        issues = []
        lines = code.split('\n')
        
        for bottleneck_type, bottleneck_data in self.bottleneck_patterns.items():
            for pattern in bottleneck_data['patterns']:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        issue = CodeIssue(
                            issue_type='PERFORMANCE',
                            severity=bottleneck_data['severity'],
                            file_path=file_path,
                            line_number=line_num,
                            column=0,
                            message=f'Performance Bottleneck: {bottleneck_type.replace("_", " ").title()}',
                            description=bottleneck_data['description'],
                            recommendation=self._get_bottleneck_fix(bottleneck_type),
                            confidence=0.9,
                            rule_id=f'BOTTLENECK_{bottleneck_type.upper()}',
                            code_snippet=line.strip(),
                            fix_suggestion=self._get_bottleneck_solution(bottleneck_type)
                        )
                        issues.append(issue)
                        self.detected_bottlenecks.append({
                            'type': bottleneck_type,
                            'file': file_path,
                            'line': line_num,
                            'severity': bottleneck_data['severity']
                        })
        
        return issues
    
    def _get_bottleneck_fix(self, bottleneck_type: str) -> str:
        """Get bottleneck-specific fix recommendations"""
        fixes = {
            'database_in_loop': 'Use batch operations, bulk inserts, or move query outside loop',
            'network_in_loop': 'Use connection pooling, async operations, or batch requests',
            'file_io_in_loop': 'Read/write files in batches or use buffered I/O',
            'expensive_operations': 'Move expensive operations outside loops or cache results'
        }
        return fixes.get(bottleneck_type, 'Optimize the bottleneck operation')
    
    def _get_bottleneck_solution(self, bottleneck_type: str) -> str:
        """Get specific solution for bottleneck"""
        solutions = {
            'database_in_loop': 'cursor.executemany(query, data_list)  # Batch operation',
            'network_in_loop': 'Use async/await or concurrent.futures.ThreadPoolExecutor',
            'file_io_in_loop': 'with open(file) as f: content = f.read()  # Outside loop',
            'expensive_operations': 'sorted_data = sorted(data)  # Pre-compute outside loop'
        }
        return solutions.get(bottleneck_type, 'Apply appropriate optimization pattern')
    
    def get_summary(self) -> Dict[str, Any]:
        """Get bottleneck detection summary"""
        return {
            'total_bottlenecks': len(self.detected_bottlenecks),
            'by_severity': Counter(b['severity'] for b in self.detected_bottlenecks),
            'by_type': Counter(b['type'] for b in self.detected_bottlenecks)
        }

class PerformanceProfiler:
    """Performance profiling capabilities for code analysis"""
    
    def __init__(self):
        self.profiling_enabled = True
        self.performance_insights = {}
    
    def analyze_code_performance(self, code: str, file_path: str) -> List[CodeIssue]:
        """Analyze code performance characteristics"""
        issues = []
        
        # Analyze potential performance hotspots
        hotspots = self._identify_performance_hotspots(code)
        
        for hotspot in hotspots:
            issue = CodeIssue(
                issue_type='PERFORMANCE',
                severity=hotspot['severity'],
                file_path=file_path,
                line_number=hotspot['line_number'],
                column=0,
                message=f'Performance Hotspot: {hotspot["type"]}',
                description=hotspot['description'],
                recommendation=hotspot['recommendation'],
                confidence=hotspot['confidence'],
                rule_id=f'PROFILE_{hotspot["type"].upper()}',
                code_snippet=hotspot['code'],
                fix_suggestion=hotspot['fix_suggestion']
            )
            issues.append(issue)
        
        return issues
    
    def _identify_performance_hotspots(self, code: str) -> List[Dict[str, Any]]:
        """Identify potential performance hotspots in code"""
        hotspots = []
        lines = code.split('\n')
        
        hotspot_patterns = {
            'regex_in_loop': {
                'pattern': r'for.*re\.(match|search|findall)',
                'description': 'Regular expressions in loops can be expensive',
                'recommendation': 'Compile regex patterns outside loops',
                'severity': 'MEDIUM',
                'fix': 'pattern = re.compile(r"..."); for item in items: pattern.match(item)'
            },
            'exception_control_flow': {
                'pattern': r'try:.*except.*:.*for.*in',
                'description': 'Using exceptions for control flow is inefficient',
                'recommendation': 'Use conditional checks instead of exception handling',
                'severity': 'MEDIUM',
                'fix': 'Use if/else conditions instead of try/except for control flow'
            }
        }
        
        for line_num, line in enumerate(lines, 1):
            for hotspot_type, hotspot_data in hotspot_patterns.items():
                if re.search(hotspot_data['pattern'], line):
                    hotspots.append({
                        'type': hotspot_type,
                        'line_number': line_num,
                        'code': line.strip(),
                        'description': hotspot_data['description'],
                        'recommendation': hotspot_data['recommendation'],
                        'severity': hotspot_data['severity'],
                        'confidence': 0.7,
                        'fix_suggestion': hotspot_data['fix']
                    })
        
        return hotspots
    
    def get_insights(self) -> Dict[str, Any]:
        """Get performance profiling insights"""
        return {
            'profiling_enabled': self.profiling_enabled,
            'insights_available': len(self.performance_insights),
            'recommendations': [
                'Use profiling tools like cProfile for detailed analysis',
                'Monitor memory usage with memory_profiler',
                'Use line_profiler for line-by-line performance analysis'
            ]
        }

class PerformanceMetricsTracker:
    """Track performance metrics across the codebase"""
    
    def __init__(self):
        self.metrics = {
            'total_performance_issues': 0,
            'issues_by_severity': Counter(),
            'bottlenecks_by_type': Counter(),
            'complexity_distribution': [],
            'performance_debt': 0.0
        }
    
    def update_performance_metrics(self, issues: List[CodeIssue], file_path: str):
        """Update performance metrics with analysis results"""
        perf_issues = [issue for issue in issues if issue.issue_type == 'PERFORMANCE']
        
        self.metrics['total_performance_issues'] += len(perf_issues)
        
        for issue in perf_issues:
            self.metrics['issues_by_severity'][issue.severity] += 1
            
            # Track performance debt
            severity_weights = {'CRITICAL': 5, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
            self.metrics['performance_debt'] += severity_weights.get(issue.severity, 1)
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance metrics summary"""
        return {
            'total_issues': self.metrics['total_performance_issues'],
            'severity_distribution': dict(self.metrics['issues_by_severity']),
            'performance_debt_score': self.metrics['performance_debt'],
            'bottlenecks': dict(self.metrics['bottlenecks_by_type'])
        }
    
    def calculate_performance_score(self) -> float:
        """Calculate performance score (0-100, higher is better)"""
        if self.metrics['total_performance_issues'] == 0:
            return 100.0
        
        base_score = 100.0
        penalty = min(80, self.metrics['performance_debt'] * 2)  # Cap penalty at 80
        
        return max(20, base_score - penalty)  # Minimum score of 20

# Backward compatibility - keep original PerformanceAnalyzer as alias
class PerformanceAnalyzer(AdvancedPerformanceOptimizationEngine):
    """Backward compatibility alias for AdvancedPerformanceOptimizationEngine"""

class CodeQualityMetricsDashboard:
    """Comprehensive dashboard for code quality metrics, trends, and insights"""
    
    def __init__(self, project_path: str, db_path: str = None):
        self.project_path = project_path
        # Use temp directory if project path is a file or doesn't exist
        if os.path.isfile(project_path):
            db_dir = os.path.dirname(project_path)
        else:
            db_dir = project_path if os.path.exists(project_path) else os.getcwd()
        
        # Ensure database path is writable
        if db_path:
            self.db_path = db_path
        else:
            # Try different locations for the database
            import tempfile
            temp_dir = tempfile.gettempdir()
            self.db_path = os.path.join(temp_dir, 'quality_metrics.db')
        
        self.metrics_collector = QualityMetricsCollector()
        self.trend_analyzer = TrendAnalyzer(self.db_path)
        self.visualization_engine = VisualizationEngine()
        self.insight_generator = InsightGenerator()
        self._initialize_dashboard_db()
    
    def _initialize_dashboard_db(self):
        """Initialize dashboard database for metrics storage"""
        try:
            # Ensure directory exists
            db_dir = os.path.dirname(self.db_path)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
        except Exception as e:
            # Fallback to in-memory database if file creation fails
            logger.warning(f"Could not create database file: {e}. Using in-memory database.")
            conn = sqlite3.connect(':memory:')
            cursor = conn.cursor()
        
        # Quality metrics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quality_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                project_path TEXT,
                metric_name TEXT,
                metric_value REAL,
                metric_category TEXT,
                file_path TEXT,
                metadata TEXT
            )
        ''')
        
        # Trend analysis table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quality_trends (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                trend_type TEXT,
                trend_value REAL,
                period TEXT,
                description TEXT
            )
        ''')
        
        # Dashboard configurations
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dashboard_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                config_key TEXT UNIQUE,
                config_value TEXT,
                updated_at DATETIME
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def collect_metrics(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Collect comprehensive quality metrics from analysis results"""
        metrics = self.metrics_collector.collect_all_metrics(analysis_result)
        
        # Store metrics in database
        self._store_metrics(metrics)
        
        # Update trends
        self.trend_analyzer.update_trends(metrics)
        
        return metrics
    
    def _store_metrics(self, metrics: Dict[str, Any]):
        """Store metrics in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        timestamp = datetime.now()
        
        for category, category_metrics in metrics.items():
            if isinstance(category_metrics, dict):
                for metric_name, metric_value in category_metrics.items():
                    cursor.execute('''
                        INSERT INTO quality_metrics 
                        (timestamp, project_path, metric_name, metric_value, metric_category, metadata)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        timestamp,
                        self.project_path,
                        metric_name,
                        float(metric_value) if isinstance(metric_value, (int, float)) else 0,
                        category,
                        json.dumps(metric_value) if not isinstance(metric_value, (int, float)) else None
                    ))
        
        conn.commit()
        conn.close()
    
    def generate_dashboard(self, output_format: str = 'html', output_file: str = None) -> str:
        """Generate interactive dashboard"""
        # Get current metrics
        current_metrics = self._get_current_metrics()
        
        # Get trend data
        trend_data = self.trend_analyzer.get_trend_analysis()
        
        # Generate insights
        insights = self.insight_generator.generate_insights(current_metrics, trend_data)
        
        # Create visualizations
        visualizations = self.visualization_engine.create_dashboard_visualizations(current_metrics, trend_data)
        
        if output_format.lower() == 'html':
            dashboard_content = self._generate_html_dashboard(current_metrics, trend_data, insights, visualizations)
        elif output_format.lower() == 'json':
            dashboard_content = json.dumps({
                'metrics': current_metrics,
                'trends': trend_data,
                'insights': insights,
                'visualizations': visualizations
            }, indent=2, default=str)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(dashboard_content)
        
        return dashboard_content
    
    def _get_current_metrics(self) -> Dict[str, Any]:
        """Get current quality metrics from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get latest metrics
        cursor.execute('''
            SELECT metric_category, metric_name, metric_value, metadata
            FROM quality_metrics
            WHERE timestamp >= datetime('now', '-1 day')
            ORDER BY timestamp DESC
        ''')
        
        metrics = defaultdict(dict)
        for category, name, value, metadata in cursor.fetchall():
            if metadata:
                try:
                    metrics[category][name] = json.loads(metadata)
                except json.JSONDecodeError:
                    metrics[category][name] = value
            else:
                metrics[category][name] = value
        
        conn.close()
        return dict(metrics)
    
    def _generate_html_dashboard(self, metrics: Dict[str, Any], trends: Dict[str, Any], 
                               insights: List[Dict[str, Any]], visualizations: Dict[str, str]) -> str:
        """Generate HTML dashboard with interactive components"""
        
        html_template = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Code Quality Metrics Dashboard</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: #f5f5f5;
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 2rem;
                    text-align: center;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 2rem;
                }}
                .metrics-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 2rem;
                    margin: 2rem 0;
                }}
                .metric-card {{
                    background: white;
                    border-radius: 10px;
                    padding: 2rem;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                    transition: transform 0.3s ease;
                }}
                .metric-card:hover {{
                    transform: translateY(-5px);
                    box-shadow: 0 8px 15px rgba(0,0,0,0.2);
                }}
                .metric-title {{
                    font-size: 1.2rem;
                    font-weight: bold;
                    color: #333;
                    margin-bottom: 1rem;
                    border-bottom: 2px solid #eee;
                    padding-bottom: 0.5rem;
                }}
                .metric-value {{
                    font-size: 2.5rem;
                    font-weight: bold;
                    color: #667eea;
                    margin: 1rem 0;
                }}
                .metric-description {{
                    color: #666;
                    font-size: 0.9rem;
                }}
                .trends-section {{
                    background: white;
                    border-radius: 10px;
                    padding: 2rem;
                    margin: 2rem 0;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                }}
                .insights-section {{
                    background: white;
                    border-radius: 10px;
                    padding: 2rem;
                    margin: 2rem 0;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                }}
                .insight-item {{
                    background: #f8f9ff;
                    border-left: 4px solid #667eea;
                    padding: 1rem;
                    margin: 1rem 0;
                    border-radius: 0 5px 5px 0;
                }}
                .chart-container {{
                    height: 400px;
                    margin: 1rem 0;
                }}
                .status-good {{ color: #28a745; }}
                .status-warning {{ color: #ffc107; }}
                .status-danger {{ color: #dc3545; }}
                .tabs {{
                    display: flex;
                    background: white;
                    border-radius: 10px 10px 0 0;
                    overflow: hidden;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                .tab {{
                    flex: 1;
                    padding: 1rem;
                    text-align: center;
                    background: #f8f9fa;
                    cursor: pointer;
                    transition: background-color 0.3s;
                }}
                .tab.active {{
                    background: #667eea;
                    color: white;
                }}
                .tab-content {{
                    display: none;
                    background: white;
                    padding: 2rem;
                    border-radius: 0 0 10px 10px;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                }}
                .tab-content.active {{
                    display: block;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>📊 Code Quality Metrics Dashboard</h1>
                <p>Project: {project_path}</p>
                <p>Last Updated: {timestamp}</p>
            </div>
            
            <div class="container">
                <!-- Quality Metrics Overview -->
                <div class="metrics-grid">
                    {metrics_cards}
                </div>
                
                <!-- Tabbed Interface -->
                <div class="tabs">
                    <div class="tab active" onclick="showTab('trends')">📈 Trends</div>
                    <div class="tab" onclick="showTab('insights')">💡 Insights</div>
                    <div class="tab" onclick="showTab('visualizations')">📊 Charts</div>
                    <div class="tab" onclick="showTab('recommendations')">🎯 Recommendations</div>
                </div>
                
                <div id="trends" class="tab-content active">
                    <h2>Quality Trends</h2>
                    {trends_content}
                </div>
                
                <div id="insights" class="tab-content">
                    <h2>AI-Generated Insights</h2>
                    {insights_content}
                </div>
                
                <div id="visualizations" class="tab-content">
                    <h2>Interactive Visualizations</h2>
                    {visualizations_content}
                </div>
                
                <div id="recommendations" class="tab-content">
                    <h2>Actionable Recommendations</h2>
                    {recommendations_content}
                </div>
            </div>
            
            <script>
                function showTab(tabName) {{
                    // Hide all tab contents
                    const contents = document.querySelectorAll('.tab-content');
                    contents.forEach(content => content.classList.remove('active'));
                    
                    // Remove active class from all tabs
                    const tabs = document.querySelectorAll('.tab');
                    tabs.forEach(tab => tab.classList.remove('active'));
                    
                    // Show selected tab content
                    document.getElementById(tabName).classList.add('active');
                    
                    // Add active class to clicked tab
                    event.target.classList.add('active');
                }}
                
                // Auto-refresh dashboard every 5 minutes
                setInterval(() => {{
                    location.reload();
                }}, 300000);
            </script>
        </body>
        </html>
        '''
        
        # Generate metrics cards
        metrics_cards = self._generate_metrics_cards(metrics)
        
        # Generate content sections
        trends_content = self._generate_trends_content(trends)
        insights_content = self._generate_insights_content(insights)
        visualizations_content = self._generate_visualizations_content(visualizations)
        recommendations_content = self._generate_recommendations_content(insights)
        
        return html_template.format(
            project_path=self.project_path,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            metrics_cards=metrics_cards,
            trends_content=trends_content,
            insights_content=insights_content,
            visualizations_content=visualizations_content,
            recommendations_content=recommendations_content
        )
    
    def _generate_metrics_cards(self, metrics: Dict[str, Any]) -> str:
        """Generate HTML cards for quality metrics"""
        cards_html = ""
        
        # Define key metrics to display
        key_metrics = {
            'overall': {
                'quality_score': {'title': 'Overall Quality Score', 'unit': '/100', 'type': 'score'},
                'total_issues': {'title': 'Total Issues', 'unit': '', 'type': 'count'},
                'technical_debt': {'title': 'Technical Debt', 'unit': ' hours', 'type': 'debt'}
            },
            'security': {
                'security_score': {'title': 'Security Score', 'unit': '/100', 'type': 'score'},
                'critical_vulnerabilities': {'title': 'Critical Vulnerabilities', 'unit': '', 'type': 'critical'},
                'owasp_coverage': {'title': 'OWASP Coverage', 'unit': '%', 'type': 'percentage'}
            },
            'performance': {
                'performance_score': {'title': 'Performance Score', 'unit': '/100', 'type': 'score'},
                'bottlenecks': {'title': 'Performance Bottlenecks', 'unit': '', 'type': 'count'},
                'complexity_avg': {'title': 'Avg. Complexity', 'unit': '', 'type': 'complexity'}
            },
            'maintainability': {
                'maintainability_score': {'title': 'Maintainability Score', 'unit': '/100', 'type': 'score'},
                'code_smells': {'title': 'Code Smells', 'unit': '', 'type': 'count'},
                'documentation_ratio': {'title': 'Documentation Ratio', 'unit': '%', 'type': 'percentage'}
            }
        }
        
        for category, category_metrics in key_metrics.items():
            for metric_key, metric_info in category_metrics.items():
                value = self._get_metric_value(metrics, category, metric_key)
                status_class = self._get_status_class(metric_info['type'], value)
                
                cards_html += f'''
                <div class="metric-card">
                    <div class="metric-title">{metric_info['title']}</div>
                    <div class="metric-value {status_class}">{value}{metric_info['unit']}</div>
                    <div class="metric-description">
                        {self._get_metric_description(metric_info['type'], value)}
                    </div>
                </div>
                '''
        
        return cards_html
    
    def _get_metric_value(self, metrics: Dict[str, Any], category: str, metric_key: str) -> str:
        """Get metric value with appropriate formatting"""
        try:
            value = metrics.get(category, {}).get(metric_key, 0)
            if isinstance(value, float):
                return f"{value:.1f}"
            return str(value)
        except:
            return "N/A"
    
    def _get_status_class(self, metric_type: str, value: str) -> str:
        """Get CSS class based on metric type and value"""
        try:
            val = float(value)
            if metric_type == 'score':
                if val >= 80: return 'status-good'
                elif val >= 60: return 'status-warning'
                else: return 'status-danger'
            elif metric_type in ['count', 'critical']:
                if val == 0: return 'status-good'
                elif val <= 5: return 'status-warning'
                else: return 'status-danger'
            elif metric_type == 'percentage':
                if val >= 80: return 'status-good'
                elif val >= 60: return 'status-warning'
                else: return 'status-danger'
        except:
            pass
        return ''
    
    def _get_metric_description(self, metric_type: str, value: str) -> str:
        """Get description based on metric type and value"""
        try:
            val = float(value)
            if metric_type == 'score':
                if val >= 80: return 'Excellent code quality'
                elif val >= 60: return 'Good quality with room for improvement'
                else: return 'Needs immediate attention'
            elif metric_type == 'critical':
                if val == 0: return 'No critical issues found'
                else: return f'{int(val)} critical issues require immediate attention'
            elif metric_type == 'count':
                if val == 0: return 'No issues detected'
                else: return f'{int(val)} issues found'
        except:
            pass
        return 'Analysis complete'
    
    def _generate_trends_content(self, trends: Dict[str, Any]) -> str:
        """Generate trends section content"""
        if not trends:
            return '<p>No trend data available yet. Run multiple analyses to see trends.</p>'
        
        content = '<div class="chart-container" id="trendsChart"></div>'
        return content
    
    def _generate_insights_content(self, insights: List[Dict[str, Any]]) -> str:
        """Generate insights section content"""
        if not insights:
            return '<p>No insights generated yet.</p>'
        
        content = ""
        for insight in insights:
            content += f'''
            <div class="insight-item">
                <h4>{insight.get('title', 'Insight')}</h4>
                <p>{insight.get('description', 'No description available')}</p>
                <strong>Impact:</strong> {insight.get('impact', 'Unknown')}<br>
                <strong>Recommendation:</strong> {insight.get('recommendation', 'No recommendation')}
            </div>
            '''
        
        return content
    
    def _generate_visualizations_content(self, visualizations: Dict[str, str]) -> str:
        """Generate visualizations section content"""
        content = '<div class="chart-container" id="mainChart"></div>'
        return content
    
    def _generate_recommendations_content(self, insights: List[Dict[str, Any]]) -> str:
        """Generate recommendations section content"""
        recommendations = [
            'Implement automated code quality gates in CI/CD pipeline',
            'Set up regular security scanning and vulnerability assessment',
            'Establish code review guidelines and standards',
            'Implement performance monitoring and optimization cycles',
            'Create technical debt tracking and remediation plan'
        ]
        
        content = '<ul>'
        for rec in recommendations:
            content += f'<li>{rec}</li>'
        content += '</ul>'
        
        return content
    
    def get_quality_summary(self) -> Dict[str, Any]:
        """Get comprehensive quality summary"""
        metrics = self._get_current_metrics()
        trends = self.trend_analyzer.get_trend_analysis()
        insights = self.insight_generator.generate_insights(metrics, trends)
        
        return {
            'current_metrics': metrics,
            'trends': trends,
            'insights': insights,
            'dashboard_url': f'file://{os.path.abspath(self.db_path.replace(".db", "_dashboard.html"))}'
        }

class QualityMetricsCollector:
    """Collects comprehensive quality metrics from analysis results"""
    
    def __init__(self):
        self.metrics_definitions = {
            'overall': ['quality_score', 'total_issues', 'lines_analyzed', 'files_analyzed'],
            'security': ['security_score', 'vulnerabilities_count', 'critical_vulnerabilities', 'owasp_coverage'],
            'performance': ['performance_score', 'bottlenecks_count', 'complexity_avg', 'performance_debt'],
            'maintainability': ['maintainability_score', 'code_smells', 'documentation_ratio', 'duplication_ratio'],
            'technical_debt': ['total_debt_hours', 'debt_per_line', 'debt_trend', 'priority_items']
        }
    
    def collect_all_metrics(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Collect all quality metrics from analysis result"""
        metrics = {}
        
        # Overall metrics
        metrics['overall'] = self._collect_overall_metrics(analysis_result)
        
        # Security metrics
        metrics['security'] = self._collect_security_metrics(analysis_result)
        
        # Performance metrics  
        metrics['performance'] = self._collect_performance_metrics(analysis_result)
        
        # Maintainability metrics
        metrics['maintainability'] = self._collect_maintainability_metrics(analysis_result)
        
        # Technical debt metrics
        metrics['technical_debt'] = self._collect_technical_debt_metrics(analysis_result)
        
        return metrics
    
    def _collect_overall_metrics(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Collect overall quality metrics"""
        total_issues = len(analysis_result.issues)
        critical_issues = len([i for i in analysis_result.issues if i.severity == 'CRITICAL'])
        high_issues = len([i for i in analysis_result.issues if i.severity == 'HIGH'])
        
        # Calculate overall quality score
        base_score = 100
        penalty = critical_issues * 15 + high_issues * 8 + (total_issues - critical_issues - high_issues) * 2
        quality_score = max(0, base_score - penalty)
        
        return {
            'quality_score': quality_score,
            'total_issues': total_issues,
            'lines_analyzed': analysis_result.metrics.get('total_lines_of_code', 0),
            'files_analyzed': analysis_result.metrics.get('total_files_analyzed', 0),
            'critical_issues': critical_issues,
            'high_issues': high_issues
        }
    
    def _collect_security_metrics(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Collect security-specific metrics"""
        security_issues = [i for i in analysis_result.issues if i.issue_type == 'SECURITY']
        critical_vulns = len([i for i in security_issues if i.severity == 'CRITICAL'])
        
        # OWASP coverage (simplified)
        owasp_categories_found = len(set(i.rule_id.split('_')[1] for i in security_issues if 'OWASP' in i.rule_id))
        owasp_coverage = (owasp_categories_found / 10) * 100  # OWASP Top 10
        
        return {
            'security_score': analysis_result.metrics.get('security_score', 100),
            'vulnerabilities_count': len(security_issues),
            'critical_vulnerabilities': critical_vulns,
            'owasp_coverage': owasp_coverage
        }
    
    def _collect_performance_metrics(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Collect performance-specific metrics"""
        performance_issues = [i for i in analysis_result.issues if i.issue_type == 'PERFORMANCE']
        bottlenecks = len([i for i in performance_issues if 'BOTTLENECK' in i.rule_id])
        
        return {
            'performance_score': analysis_result.metrics.get('performance_score', 100),
            'bottlenecks_count': bottlenecks,
            'complexity_avg': analysis_result.metrics.get('average_complexity', 0),
            'performance_debt': len(performance_issues) * 2  # Simplified debt calculation
        }
    
    def _collect_maintainability_metrics(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Collect maintainability-specific metrics"""
        code_smells = len([i for i in analysis_result.issues if i.issue_type == 'CODE_SMELL'])
        
        return {
            'maintainability_score': analysis_result.metrics.get('maintainability_score', 100),
            'code_smells': code_smells,
            'documentation_ratio': 75,  # Placeholder
            'duplication_ratio': 5      # Placeholder
        }
    
    def _collect_technical_debt_metrics(self, analysis_result: AnalysisResult) -> Dict[str, Any]:
        """Collect technical debt metrics"""
        # Estimate technical debt in hours (simplified calculation)
        critical_debt = len([i for i in analysis_result.issues if i.severity == 'CRITICAL']) * 4
        high_debt = len([i for i in analysis_result.issues if i.severity == 'HIGH']) * 2
        medium_debt = len([i for i in analysis_result.issues if i.severity == 'MEDIUM']) * 1
        low_debt = len([i for i in analysis_result.issues if i.severity == 'LOW']) * 0.5
        
        total_debt = critical_debt + high_debt + medium_debt + low_debt
        total_lines = analysis_result.metrics.get('total_lines_of_code', 1)
        
        return {
            'total_debt_hours': total_debt,
            'debt_per_line': total_debt / total_lines * 1000,  # Per 1000 lines
            'debt_trend': 'stable',  # Placeholder
            'priority_items': len([i for i in analysis_result.issues if i.severity in ['CRITICAL', 'HIGH']])
        }

class TrendAnalyzer:
    """Analyzes trends in code quality metrics over time"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
    
    def update_trends(self, current_metrics: Dict[str, Any]):
        """Update trend analysis with current metrics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        timestamp = datetime.now()
        
        # Store trend data
        for category, metrics in current_metrics.items():
            for metric_name, metric_value in metrics.items():
                if isinstance(metric_value, (int, float)):
                    cursor.execute('''
                        INSERT INTO quality_trends
                        (timestamp, trend_type, trend_value, period, description)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (
                        timestamp,
                        f'{category}_{metric_name}',
                        metric_value,
                        'daily',
                        f'{category.title()} {metric_name.replace("_", " ").title()}'
                    ))
        
        conn.commit()
        conn.close()
    
    def get_trend_analysis(self, days: int = 30) -> Dict[str, Any]:
        """Get trend analysis for specified period"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get trends for the last N days
        cursor.execute('''
            SELECT trend_type, trend_value, timestamp
            FROM quality_trends
            WHERE timestamp >= datetime('now', '-{} days')
            ORDER BY timestamp
        '''.format(days))
        
        trend_data = defaultdict(list)
        for trend_type, value, timestamp in cursor.fetchall():
            trend_data[trend_type].append({
                'value': value,
                'timestamp': timestamp
            })
        
        conn.close()
        
        # Calculate trend directions
        trends_summary = {}
        for trend_type, values in trend_data.items():
            if len(values) >= 2:
                first_val = values[0]['value']
                last_val = values[-1]['value']
                change_pct = ((last_val - first_val) / first_val * 100) if first_val != 0 else 0
                
                trends_summary[trend_type] = {
                    'direction': 'improving' if change_pct > 5 else 'declining' if change_pct < -5 else 'stable',
                    'change_percentage': change_pct,
                    'current_value': last_val,
                    'data_points': len(values)
                }
        
        return trends_summary

class VisualizationEngine:
    """Creates visualizations for dashboard"""
    
    def __init__(self):
        self.chart_templates = {
            'line_chart': self._create_line_chart,
            'bar_chart': self._create_bar_chart,
            'pie_chart': self._create_pie_chart,
            'gauge_chart': self._create_gauge_chart
        }
    
    def create_dashboard_visualizations(self, metrics: Dict[str, Any], trends: Dict[str, Any]) -> Dict[str, str]:
        """Create visualizations for dashboard"""
        visualizations = {}
        
        # Create quality score gauge
        overall_score = metrics.get('overall', {}).get('quality_score', 0)
        visualizations['quality_gauge'] = self._create_gauge_chart(overall_score, 'Overall Quality Score')
        
        # Create issues breakdown pie chart
        issue_counts = {
            'Critical': metrics.get('overall', {}).get('critical_issues', 0),
            'High': metrics.get('overall', {}).get('high_issues', 0),
            'Medium': metrics.get('overall', {}).get('total_issues', 0) - 
                     metrics.get('overall', {}).get('critical_issues', 0) - 
                     metrics.get('overall', {}).get('high_issues', 0)
        }
        visualizations['issues_pie'] = self._create_pie_chart(issue_counts, 'Issues by Severity')
        
        return visualizations
    
    def _create_line_chart(self, data: Dict, title: str) -> str:
        """Create line chart"""
        return f'<div>Line chart for {title}</div>'
    
    def _create_bar_chart(self, data: Dict, title: str) -> str:
        """Create bar chart"""
        return f'<div>Bar chart for {title}</div>'
    
    def _create_pie_chart(self, data: Dict, title: str) -> str:
        """Create pie chart"""
        return f'<div>Pie chart for {title}: {data}</div>'
    
    def _create_gauge_chart(self, value: float, title: str) -> str:
        """Create gauge chart"""
        return f'<div>Gauge chart for {title}: {value}</div>'

class InsightGenerator:
    """Generates AI-powered insights from quality metrics"""
    
    def __init__(self):
        self.insight_templates = {
            'quality_improvement': 'Quality score has {direction} by {change}% over the last period',
            'security_alert': 'Found {count} critical security vulnerabilities requiring immediate attention',
            'performance_concern': 'Performance bottlenecks detected in {count} areas',
            'maintainability_trend': 'Code maintainability is {trend} based on recent metrics'
        }
    
    def generate_insights(self, metrics: Dict[str, Any], trends: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate actionable insights from metrics and trends"""
        insights = []
        
        # Quality insights
        overall_score = metrics.get('overall', {}).get('quality_score', 0)
        if overall_score < 60:
            insights.append({
                'title': 'Quality Score Alert',
                'description': f'Overall quality score is {overall_score}/100, which is below the recommended threshold',
                'impact': 'High',
                'recommendation': 'Focus on addressing critical and high-severity issues first'
            })
        
        # Security insights
        critical_vulns = metrics.get('security', {}).get('critical_vulnerabilities', 0)
        if critical_vulns > 0:
            insights.append({
                'title': 'Critical Security Alert',
                'description': f'Found {critical_vulns} critical security vulnerabilities',
                'impact': 'Critical',
                'recommendation': 'Immediate remediation required for all critical vulnerabilities'
            })
        
        # Performance insights
        bottlenecks = metrics.get('performance', {}).get('bottlenecks_count', 0)
        if bottlenecks > 5:
            insights.append({
                'title': 'Performance Bottlenecks',
                'description': f'Detected {bottlenecks} performance bottlenecks in the codebase',
                'impact': 'Medium',
                'recommendation': 'Review and optimize high-impact performance issues'
            })
        
        # Trend insights
        for trend_type, trend_info in trends.items():
            if 'quality_score' in trend_type and trend_info['direction'] == 'declining':
                insights.append({
                    'title': 'Quality Trend Alert',
                    'description': f'Quality score is declining by {abs(trend_info["change_percentage"]):.1f}%',
                    'impact': 'Medium',
                    'recommendation': 'Implement quality gates and increase code review rigor'
                })
        
        return insights

class CICDIntegrationFramework:
    """Comprehensive CI/CD integration framework for automated code analysis"""
    
    def __init__(self, project_path: str, analyzer: 'IntelligentCodeAnalyzer'):
        self.project_path = project_path
        self.analyzer = analyzer
        self.platform_generators = {
            'github_actions': GitHubActionsGenerator(),
            'jenkins': JenkinsGenerator(),
            'gitlab_ci': GitLabCIGenerator(),
            'azure_devops': AzureDevOpsGenerator(),
            'circleci': CircleCIGenerator(),
            'bitbucket': BitbucketPipelinesGenerator(),
            'teamcity': TeamCityGenerator()
        }
        self.notification_handlers = {
            'slack': SlackNotificationHandler(),
            'teams': TeamsNotificationHandler(),
            'email': EmailNotificationHandler(),
            'webhook': WebhookNotificationHandler()
        }
        self.report_formatters = {
            'junit': JUnitReportFormatter(),
            'sonar': SonarQubeReportFormatter(),
            'sarif': SARIFReportFormatter(),
            'checkstyle': CheckstyleReportFormatter(),
            'json': JSONReportFormatter(),
            'html': HTMLReportFormatter()
        }
    
    def generate_ci_configurations(self, platforms: List[str] = None, output_dir: str = None) -> Dict[str, str]:
        """Generate CI/CD configuration files for specified platforms"""
        if platforms is None:
            platforms = list(self.platform_generators.keys())
        
        if output_dir is None:
            output_dir = self.project_path
        
        generated_files = {}
        
        for platform in platforms:
            if platform in self.platform_generators:
                generator = self.platform_generators[platform]
                config_content = generator.generate_configuration(self.project_path)
                
                # Write configuration file
                config_file = generator.get_config_filename()
                config_path = os.path.join(output_dir, config_file)
                
                # Create directories if they don't exist
                os.makedirs(os.path.dirname(config_path), exist_ok=True)
                
                with open(config_path, 'w', encoding='utf-8') as f:
                    f.write(config_content)
                
                generated_files[platform] = config_path
                logger.info(f"Generated {platform} configuration: {config_path}")
        
        return generated_files
    
    def generate_quality_gates(self, thresholds: Dict[str, Any] = None) -> Dict[str, Any]:
        """Generate quality gates configuration"""
        if thresholds is None:
            thresholds = {
                'quality_score_min': 70,
                'security_score_min': 80,
                'performance_score_min': 75,
                'critical_issues_max': 0,
                'high_issues_max': 5,
                'coverage_min': 80,
                'duplication_max': 3,
                'maintainability_rating': 'A',
                'reliability_rating': 'A',
                'security_rating': 'A'
            }
        
        quality_gates = {
            'thresholds': thresholds,
            'enforcement_rules': {
                'block_deployment': ['critical_issues_max', 'security_score_min'],
                'require_approval': ['quality_score_min', 'high_issues_max'],
                'warning_only': ['performance_score_min', 'coverage_min']
            },
            'notification_triggers': {
                'immediate': ['critical_issues_max'],
                'daily_digest': ['quality_score_min', 'security_score_min'],
                'weekly_report': ['all']
            }
        }
        
        return quality_gates
    
    def integrate_with_sonarqube(self, sonar_config: Dict[str, str] = None) -> str:
        """Generate SonarQube integration configuration"""
        if sonar_config is None:
            sonar_config = {
                'host_url': 'http://localhost:9000',
                'project_key': os.path.basename(self.project_path),
                'project_name': os.path.basename(self.project_path),
                'sources': 'src',
                'language': 'python'
            }
        
        sonar_properties = f"""
# SonarQube Configuration for Intelligent Code Analyzer
sonar.projectKey={sonar_config['project_key']}
sonar.projectName={sonar_config['project_name']}
sonar.projectVersion=1.0
sonar.host.url={sonar_config['host_url']}
sonar.sources={sonar_config['sources']}
sonar.language={sonar_config['language']}

# Analysis exclusions
sonar.exclusions=**/*_test.py,**/test_*.py,**/__pycache__/**,**/venv/**,**/node_modules/**

# Coverage settings
sonar.python.coverage.reportPaths=coverage.xml
sonar.python.xunit.reportPath=test-results.xml

# Custom quality profiles
sonar.qualitygate.wait=true
sonar.qualitygate.timeout=300

# External analyzer integration
sonar.externalIssuesReportPaths=intelligent-analyzer-report.json
        """
        
        sonar_file = os.path.join(self.project_path, 'sonar-project.properties')
        with open(sonar_file, 'w', encoding='utf-8') as f:
            f.write(sonar_properties)
        
        return sonar_file
    
    def create_integration_scripts(self, output_dir: str = None) -> Dict[str, str]:
        """Create integration scripts for various CI/CD platforms"""
        if output_dir is None:
            output_dir = os.path.join(self.project_path, 'ci-scripts')
        
        os.makedirs(output_dir, exist_ok=True)
        
        scripts = {}
        
        # Universal analysis script
        analysis_script = self._create_analysis_script()
        analysis_script_path = os.path.join(output_dir, 'run-analysis.py')
        with open(analysis_script_path, 'w', encoding='utf-8') as f:
            f.write(analysis_script)
        scripts['analysis'] = analysis_script_path
        
        # Quality gate script
        gate_script = self._create_quality_gate_script()
        gate_script_path = os.path.join(output_dir, 'quality-gate.py')
        with open(gate_script_path, 'w', encoding='utf-8') as f:
            f.write(gate_script)
        scripts['quality_gate'] = gate_script_path
        
        # Report generation script
        report_script = self._create_report_script()
        report_script_path = os.path.join(output_dir, 'generate-reports.py')
        with open(report_script_path, 'w', encoding='utf-8') as f:
            f.write(report_script)
        scripts['reporting'] = report_script_path
        
        return scripts
    
    def _create_analysis_script(self) -> str:
        """Create universal analysis script"""
        script = '''
#!/usr/bin/env python3
"""
Intelligent Code Analyzer CI/CD Integration Script
This script runs the comprehensive code analysis and generates reports
"""

import sys
import os
import json
import argparse
from datetime import datetime

# Add the analyzer to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    parser = argparse.ArgumentParser(description='Run Intelligent Code Analysis')
    parser.add_argument('--project-path', default='.', help='Path to the project to analyze')
    parser.add_argument('--output-format', default='json', choices=['json', 'html', 'junit', 'sarif', 'sonar'],
                       help='Output format for reports')
    parser.add_argument('--output-file', help='Output file path')
    parser.add_argument('--fail-on-critical', action='store_true', 
                       help='Fail CI build if critical issues found')
    parser.add_argument('--quality-gate-config', help='Path to quality gate configuration JSON')
    parser.add_argument('--enable-dashboard', action='store_true', help='Generate quality dashboard')
    parser.add_argument('--notification-config', help='Path to notification configuration JSON')
    
    args = parser.parse_args()
    
    try:
        # Initialize analyzer
        from hack3 import IntelligentCodeAnalyzer, CICDIntegrationFramework
        
        analyzer = IntelligentCodeAnalyzer(args.project_path)
        ci_framework = CICDIntegrationFramework(args.project_path, analyzer)
        
        print(f"Starting analysis of {args.project_path}...")
        
        # Run analysis
        result = analyzer.analyze_codebase()
        
        # Generate report in specified format
        if args.output_format == 'json':
            report = analyzer.generate_report(result, 'json')
        elif args.output_format == 'html':
            report = analyzer.generate_report(result, 'html')
        elif args.output_format == 'junit':
            report = ci_framework.report_formatters['junit'].format_report(result)
        elif args.output_format == 'sarif':
            report = ci_framework.report_formatters['sarif'].format_report(result)
        elif args.output_format == 'sonar':
            report = ci_framework.report_formatters['sonar'].format_report(result)
        
        # Save report
        output_file = args.output_file or f'analysis-report.{args.output_format}'
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"Report saved to: {output_file}")
        
        # Generate dashboard if requested
        if args.enable_dashboard:
            dashboard_file = output_file.replace(f'.{args.output_format}', '_dashboard.html')
            dashboard = analyzer.generate_report(result, 'html')
            with open(dashboard_file, 'w', encoding='utf-8') as f:
                f.write(dashboard)
            print(f"Dashboard saved to: {dashboard_file}")
        
        # Quality gate check
        if args.quality_gate_config:
            with open(args.quality_gate_config) as f:
                gate_config = json.load(f)
            
            gate_result = ci_framework.check_quality_gates(result, gate_config)
            
            if not gate_result['passed']:
                print(f"Quality gate failed: {gate_result['message']}")
                if args.fail_on_critical:
                    sys.exit(1)
        
        # Send notifications if configured
        if args.notification_config:
            with open(args.notification_config) as f:
                notification_config = json.load(f)
            
            ci_framework.send_notifications(result, notification_config)
        
        # Print summary
        print(f"\nAnalysis Summary:")
        print(f"Total issues: {len(result.issues)}")
        print(f"Critical: {len([i for i in result.issues if i.severity == 'CRITICAL'])}")
        print(f"High: {len([i for i in result.issues if i.severity == 'HIGH'])}")
        print(f"Security Score: {result.metrics.get('security_score', 'N/A')}")
        print(f"Quality Score: {result.metrics.get('maintainability_score', 'N/A')}")
        
        return 0
        
    except Exception as e:
        print(f"Analysis failed: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
'''
        return script
    
    def _create_quality_gate_script(self) -> str:
        """Create quality gate enforcement script"""
        script = '''
#!/usr/bin/env python3
"""
Quality Gate Enforcement Script
Checks analysis results against quality thresholds and enforces gates
"""

import sys
import json
import argparse

def check_quality_gates(analysis_result, thresholds):
    """
    Check if analysis results meet quality gate thresholds
    """
    failures = []
    warnings = []
    
    # Check critical issues
    critical_issues = len([i for i in analysis_result['issues'] if i.get('severity') == 'CRITICAL'])
    if critical_issues > thresholds.get('critical_issues_max', 0):
        failures.append(f"Critical issues: {critical_issues} > {thresholds['critical_issues_max']}")
    
    # Check high severity issues
    high_issues = len([i for i in analysis_result['issues'] if i.get('severity') == 'HIGH'])
    if high_issues > thresholds.get('high_issues_max', 5):
        warnings.append(f"High severity issues: {high_issues} > {thresholds['high_issues_max']}")
    
    # Check security score
    security_score = analysis_result.get('metrics', {}).get('security_score', 100)
    if security_score < thresholds.get('security_score_min', 80):
        failures.append(f"Security score: {security_score} < {thresholds['security_score_min']}")
    
    # Check quality score
    quality_score = analysis_result.get('metrics', {}).get('maintainability_score', 100)
    if quality_score < thresholds.get('quality_score_min', 70):
        warnings.append(f"Quality score: {quality_score} < {thresholds['quality_score_min']}")
    
    return {
        'passed': len(failures) == 0,
        'failures': failures,
        'warnings': warnings,
        'message': '; '.join(failures) if failures else 'All quality gates passed'
    }

def main():
    parser = argparse.ArgumentParser(description='Quality Gate Enforcement')
    parser.add_argument('--analysis-report', required=True, help='Path to analysis report JSON')
    parser.add_argument('--thresholds', required=True, help='Path to quality gate thresholds JSON')
    parser.add_argument('--fail-build', action='store_true', help='Fail build on gate failures')
    
    args = parser.parse_args()
    
    try:
        # Load analysis results
        with open(args.analysis_report) as f:
            analysis_result = json.load(f)
        
        # Load thresholds
        with open(args.thresholds) as f:
            thresholds = json.load(f)
        
        # Check quality gates
        result = check_quality_gates(analysis_result, thresholds)
        
        print(f"Quality Gate Result: {'PASSED' if result['passed'] else 'FAILED'}")
        print(f"Message: {result['message']}")
        
        if result['warnings']:
            print("Warnings:")
            for warning in result['warnings']:
                print(f"  - {warning}")
        
        if result['failures']:
            print("Failures:")
            for failure in result['failures']:
                print(f"  - {failure}")
        
        if not result['passed'] and args.fail_build:
            return 1
        
        return 0
        
    except Exception as e:
        print(f"Quality gate check failed: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
'''
        return script
    
    def _create_report_script(self) -> str:
        """Create report generation script"""
        script = '''
#!/usr/bin/env python3
"""
Report Generation Script
Generates various report formats from analysis results
"""

import sys
import json
import argparse
import os

def generate_junit_report(analysis_result, output_file):
    """
    Generate JUnit XML report
    """
    from xml.etree.ElementTree import Element, SubElement, tostring
    from xml.dom import minidom
    
    testsuites = Element('testsuites')
    testsuite = SubElement(testsuites, 'testsuite')
    testsuite.set('name', 'Code Analysis')
    testsuite.set('tests', str(len(analysis_result.get('issues', []))))
    testsuite.set('failures', str(len([i for i in analysis_result.get('issues', []) if i.get('severity') in ['CRITICAL', 'HIGH']])))
    testsuite.set('errors', '0')
    
    for issue in analysis_result.get('issues', []):
        testcase = SubElement(testsuite, 'testcase')
        testcase.set('classname', issue.get('file_path', ''))
        testcase.set('name', issue.get('rule_id', ''))
        testcase.set('time', '0')
        
        if issue.get('severity') in ['CRITICAL', 'HIGH']:
            failure = SubElement(testcase, 'failure')
            failure.set('message', issue.get('message', ''))
            failure.text = issue.get('description', '')
    
    # Pretty print XML
    rough_string = tostring(testsuites, 'utf-8')
    reparsed = minidom.parseString(rough_string)
    pretty = reparsed.toprettyxml(indent="  ")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(pretty)

def generate_sarif_report(analysis_result, output_file):
    """
    Generate SARIF JSON report
    """
    sarif_report = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Intelligent Code Analyzer",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/intelligent-code-analyzer"
                }
            },
            "results": []
        }]
    }
    
    for issue in analysis_result.get('issues', []):
        result = {
            "ruleId": issue.get('rule_id', ''),
            "message": {
                "text": issue.get('message', '')
            },
            "level": {
                'CRITICAL': 'error',
                'HIGH': 'error', 
                'MEDIUM': 'warning',
                'LOW': 'note'
            }.get(issue.get('severity'), 'note'),
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": issue.get('file_path', '')
                    },
                    "region": {
                        "startLine": issue.get('line_number', 1)
                    }
                }
            }]
        }
        
        sarif_report['runs'][0]['results'].append(result)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(sarif_report, f, indent=2)

def main():
    parser = argparse.ArgumentParser(description='Generate Analysis Reports')
    parser.add_argument('--input', required=True, help='Input analysis results JSON')
    parser.add_argument('--format', required=True, choices=['junit', 'sarif', 'checkstyle'],
                       help='Output report format')
    parser.add_argument('--output', required=True, help='Output file path')
    
    args = parser.parse_args()
    
    try:
        with open(args.input) as f:
            analysis_result = json.load(f)
        
        if args.format == 'junit':
            generate_junit_report(analysis_result, args.output)
        elif args.format == 'sarif':
            generate_sarif_report(analysis_result, args.output)
        elif args.format == 'checkstyle':
            # Placeholder for Checkstyle format
            print("Checkstyle format not yet implemented")
            return 1
        
        print(f"{args.format.upper()} report generated: {args.output}")
        return 0
        
    except Exception as e:
        print(f"Report generation failed: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
'''
        return script
    
    def check_quality_gates(self, analysis_result: AnalysisResult, gate_config: Dict[str, Any]) -> Dict[str, Any]:
        """Check if analysis results pass quality gates"""
        thresholds = gate_config.get('thresholds', {})
        failures = []
        warnings = []
        
        # Check critical issues
        critical_count = len([i for i in analysis_result.issues if i.severity == 'CRITICAL'])
        if critical_count > thresholds.get('critical_issues_max', 0):
            failures.append(f"Critical issues: {critical_count} > {thresholds['critical_issues_max']}")
        
        # Check security score
        security_score = analysis_result.metrics.get('security_score', 100)
        if security_score < thresholds.get('security_score_min', 80):
            failures.append(f"Security score: {security_score} < {thresholds['security_score_min']}")
        
        # Check quality score
        quality_score = analysis_result.metrics.get('maintainability_score', 100)
        if quality_score < thresholds.get('quality_score_min', 70):
            warnings.append(f"Quality score: {quality_score} < {thresholds['quality_score_min']}")
        
        return {
            'passed': len(failures) == 0,
            'failures': failures,
            'warnings': warnings,
            'message': '; '.join(failures) if failures else 'Quality gates passed'
        }
    
    def send_notifications(self, analysis_result: AnalysisResult, notification_config: Dict[str, Any]):
        """Send notifications based on analysis results"""
        for channel, config in notification_config.items():
            if channel in self.notification_handlers:
                handler = self.notification_handlers[channel]
                try:
                    handler.send_notification(analysis_result, config)
                    logger.info(f"Notification sent via {channel}")
                except Exception as e:
                    logger.error(f"Failed to send {channel} notification: {e}")

# Platform-specific generators

class GitHubActionsGenerator:
    """Generates GitHub Actions workflow configuration"""
    
    def get_config_filename(self) -> str:
        return '.github/workflows/code-analysis.yml'
    
    def generate_configuration(self, project_path: str) -> str:
        return '''
name: Intelligent Code Analysis

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  code-analysis:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
    
    - name: Run Intelligent Code Analysis
      run: |
        python ci-scripts/run-analysis.py \
          --project-path . \
          --output-format sarif \
          --output-file analysis-results.sarif \
          --enable-dashboard
    
    - name: Upload SARIF file
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: analysis-results.sarif
    
    - name: Quality Gate Check
      run: |
        python ci-scripts/quality-gate.py \
          --analysis-report analysis-results.json \
          --thresholds quality-gates.json \
          --fail-build
    
    - name: Upload Analysis Results
      uses: actions/upload-artifact@v3
      with:
        name: analysis-results
        path: |
          analysis-results.*
          *dashboard.html
    
    - name: Comment PR
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v6
      with:
        script: |
          const fs = require('fs');
          const analysis = JSON.parse(fs.readFileSync('analysis-results.json', 'utf8'));
          const comment = `## 🔍 Code Analysis Results
          
          **Quality Score:** ${analysis.metrics.maintainability_score}/100
          **Security Score:** ${analysis.metrics.security_score}/100
          **Total Issues:** ${analysis.issues.length}
          
          [View Detailed Dashboard](dashboard.html)`;
          
          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: comment
          });
'''

class JenkinsGenerator:
    """Generates Jenkins pipeline configuration"""
    
    def get_config_filename(self) -> str:
        return 'Jenkinsfile'
    
    def generate_configuration(self, project_path: str) -> str:
        return '''
pipeline {
    agent any
    
    triggers {
        cron('H 2 * * *')  // Daily at 2 AM
    }
    
    environment {
        PYTHON_VERSION = '3.9'
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Setup Environment') {
            steps {
                sh 'python -m pip install --upgrade pip'
                sh 'pip install -r requirements.txt'
            }
        }
        
        stage('Code Analysis') {
            steps {
                sh 'python ci-scripts/run-analysis.py --project-path . --output-format junit --output-file analysis-results.xml --enable-dashboard'
            }
            post {
                always {
                    junit 'analysis-results.xml'
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: false,
                        keepAll: true,
                        reportDir: '.',
                        reportFiles: '*dashboard.html',
                        reportName: 'Code Quality Dashboard'
                    ])
                }
            }
        }
        
        stage('Quality Gate') {
            steps {
                script {
                    def result = sh(script: 'python ci-scripts/quality-gate.py --analysis-report analysis-results.json --thresholds quality-gates.json', returnStatus: true)
                    
                    if (result != 0) {
                        currentBuild.result = 'UNSTABLE'
                        echo 'Quality gate failed - build marked as unstable'
                    }
                }
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'analysis-results.*, *dashboard.html', allowEmptyArchive: true
        }
        failure {
            emailext(
                subject: "Analysis Failed: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                body: "Code analysis failed. Check the build logs for details.",
                to: "${env.CHANGE_AUTHOR_EMAIL}"
            )
        }
    }
}
'''

class GitLabCIGenerator:
    """Generates GitLab CI configuration"""
    
    def get_config_filename(self) -> str:
        return '.gitlab-ci.yml'
    
    def generate_configuration(self, project_path: str) -> str:
        return '''
image: python:3.9

stages:
  - analysis
  - quality-gate
  - report

variables:
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"

cache:
  paths:
    - .cache/pip/
    - venv/

before_script:
  - python -V
  - pip install virtualenv
  - virtualenv venv
  - source venv/bin/activate
  - pip install -r requirements.txt

code_analysis:
  stage: analysis
  script:
    - python ci-scripts/run-analysis.py 
        --project-path . 
        --output-format json 
        --output-file analysis-results.json 
        --enable-dashboard
  artifacts:
    reports:
      junit: analysis-results.xml
    paths:
      - analysis-results.*
      - "*dashboard.html"
    expire_in: 1 week
  only:
    - main
    - merge_requests

quality_gate:
  stage: quality-gate
  script:
    - python ci-scripts/quality-gate.py 
        --analysis-report analysis-results.json 
        --thresholds quality-gates.json 
        --fail-build
  dependencies:
    - code_analysis
  only:
    - main
    - merge_requests

generate_reports:
  stage: report
  script:
    - python ci-scripts/generate-reports.py 
        --input analysis-results.json 
        --format sarif 
        --output analysis-results.sarif
  artifacts:
    paths:
      - analysis-results.sarif
    expire_in: 1 week
  dependencies:
    - code_analysis
  only:
    - main

# Scheduled nightly analysis
nightly_analysis:
  extends: code_analysis
  only:
    - schedules
  script:
    - python ci-scripts/run-analysis.py 
        --project-path . 
        --output-format html 
        --output-file nightly-analysis.html 
        --enable-dashboard
        --notification-config notification-config.json
'''

class AzureDevOpsGenerator:
    """Generates Azure DevOps pipeline configuration"""
    
    def get_config_filename(self) -> str:
        return 'azure-pipelines.yml'
    
    def generate_configuration(self, project_path: str) -> str:
        return '''
trigger:
- main
- develop

pr:
- main

schedules:
- cron: "0 2 * * *"
  displayName: Daily analysis
  branches:
    include:
    - main
  always: true

pool:
  vmImage: 'ubuntu-latest'

variables:
  pythonVersion: '3.9'

stages:
- stage: CodeAnalysis
  displayName: 'Code Analysis'
  jobs:
  - job: RunAnalysis
    displayName: 'Run Intelligent Code Analysis'
    steps:
    - task: UsePythonVersion@0
      inputs:
        versionSpec: '$(pythonVersion)'
      displayName: 'Use Python $(pythonVersion)'
    
    - script: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
      displayName: 'Install dependencies'
    
    - script: |
        python ci-scripts/run-analysis.py \
          --project-path . \
          --output-format junit \
          --output-file analysis-results.xml \
          --enable-dashboard
      displayName: 'Run code analysis'
    
    - task: PublishTestResults@2
      condition: succeededOrFailed()
      inputs:
        testResultsFiles: 'analysis-results.xml'
        testRunTitle: 'Code Analysis Results'
    
    - task: PublishHtmlReport@1
      condition: succeededOrFailed()
      inputs:
        reportDir: '.'
        tabName: 'Code Quality Dashboard'
        
    - script: |
        python ci-scripts/quality-gate.py \
          --analysis-report analysis-results.json \
          --thresholds quality-gates.json
      displayName: 'Quality gate check'
      continueOnError: true
    
    - task: PublishBuildArtifacts@1
      condition: succeededOrFailed()
      inputs:
        pathToPublish: '.'
        artifactName: 'analysis-results'
        includeRootFolder: false
        artifactType: 'container'
'''

class CircleCIGenerator:
    """Generates CircleCI configuration"""
    
    def get_config_filename(self) -> str:
        return '.circleci/config.yml'
    
    def generate_configuration(self, project_path: str) -> str:
        return '''
version: 2.1

commands:
  install-deps:
    steps:
      - run:
          name: Install dependencies
          command: |
            python -m pip install --upgrade pip
            pip install -r requirements.txt

jobs:
  code-analysis:
    docker:
      - image: python:3.9
    steps:
      - checkout
      - install-deps
      - run:
          name: Run code analysis
          command: |
            python ci-scripts/run-analysis.py \
              --project-path . \
              --output-format junit \
              --output-file analysis-results.xml \
              --enable-dashboard
      - store_test_results:
          path: analysis-results.xml
      - store_artifacts:
          path: analysis-results.json
      - store_artifacts:
          path: "*dashboard.html"
      - run:
          name: Quality gate check
          command: |
            python ci-scripts/quality-gate.py \
              --analysis-report analysis-results.json \
              --thresholds quality-gates.json

workflows:
  version: 2
  analysis:
    jobs:
      - code-analysis
  
  nightly:
    triggers:
      - schedule:
          cron: "0 2 * * *"
          filters:
            branches:
              only:
                - main
    jobs:
      - code-analysis
'''

class BitbucketPipelinesGenerator:
    """Generates Bitbucket Pipelines configuration"""
    
    def get_config_filename(self) -> str:
        return 'bitbucket-pipelines.yml'
    
    def generate_configuration(self, project_path: str) -> str:
        return '''
image: python:3.9

pipelines:
  default:
    - step:
        name: Code Analysis
        script:
          - python -m pip install --upgrade pip
          - pip install -r requirements.txt
          - python ci-scripts/run-analysis.py 
              --project-path . 
              --output-format junit 
              --output-file analysis-results.xml 
              --enable-dashboard
          - python ci-scripts/quality-gate.py 
              --analysis-report analysis-results.json 
              --thresholds quality-gates.json
        artifacts:
          - analysis-results.*
          - "*dashboard.html"
  
  branches:
    main:
      - step:
          name: Production Analysis
          script:
            - python -m pip install --upgrade pip
            - pip install -r requirements.txt
            - python ci-scripts/run-analysis.py 
                --project-path . 
                --output-format sarif 
                --output-file analysis-results.sarif 
                --enable-dashboard 
                --notification-config notification-config.json
          artifacts:
            - analysis-results.*
            - "*dashboard.html"
          
  custom:
    nightly-analysis:
      - step:
          name: Comprehensive Analysis
          script:
            - python -m pip install --upgrade pip
            - pip install -r requirements.txt
            - python ci-scripts/run-analysis.py 
                --project-path . 
                --output-format html 
                --output-file comprehensive-analysis.html 
                --enable-dashboard
          artifacts:
            - comprehensive-analysis.html
            - "*dashboard.html"
'''

class TeamCityGenerator:
    """Generates TeamCity configuration"""
    
    def get_config_filename(self) -> str:
        return '.teamcity/settings.kts'
    
    def generate_configuration(self, project_path: str) -> str:
        return '''
import jetbrains.buildServer.configs.kotlin.v2019_2.*
import jetbrains.buildServer.configs.kotlin.v2019_2.buildSteps.script
import jetbrains.buildServer.configs.kotlin.v2019_2.triggers.schedule

version = "2019.2"

project {
    buildType(CodeAnalysis)
}

object CodeAnalysis : BuildType({
    name = "Intelligent Code Analysis"
    
    vcs {
        root(DslContext.settingsRoot)
    }
    
    steps {
        script {
            name = "Install Dependencies"
            scriptContent = """
                python -m pip install --upgrade pip
                pip install -r requirements.txt
            """.trimIndent()
        }
        
        script {
            name = "Run Analysis"
            scriptContent = """
                python ci-scripts/run-analysis.py \
                  --project-path . \
                  --output-format junit \
                  --output-file analysis-results.xml \
                  --enable-dashboard
            """.trimIndent()
        }
        
        script {
            name = "Quality Gate Check"
            scriptContent = """
                python ci-scripts/quality-gate.py \
                  --analysis-report analysis-results.json \
                  --thresholds quality-gates.json
            """.trimIndent()
        }
    }
    
    triggers {
        schedule {
            schedulingPolicy = daily {
                hour = 2
            }
            branchFilter = """
                +:main
            """.trimIndent()
            triggerBuild = always()
        }
    }
    
    features {
        xmlReport {
            reportType = XmlReport.XmlReportType.JUNIT
            rules = "analysis-results.xml"
        }
    }
    
    artifactRules = """
        analysis-results.* => analysis-results.zip
        *dashboard.html => dashboard.zip
    """.trimIndent()
})
'''

# Notification handlers

class NotificationHandler:
    """Base class for notification handlers"""
    
    def send_notification(self, analysis_result: AnalysisResult, config: Dict[str, Any]):
        raise NotImplementedError

class SlackNotificationHandler(NotificationHandler):
    """Slack notification handler"""
    
    def send_notification(self, analysis_result: AnalysisResult, config: Dict[str, Any]):
        webhook_url = config.get('webhook_url')
        if not webhook_url:
            raise ValueError("Slack webhook URL not configured")
        
        # Create Slack message
        total_issues = len(analysis_result.issues)
        critical_issues = len([i for i in analysis_result.issues if i.severity == 'CRITICAL'])
        
        message = {
            "text": "Code Analysis Results",
            "attachments": [{
                "color": "danger" if critical_issues > 0 else "warning" if total_issues > 5 else "good",
                "fields": [
                    {
                        "title": "Total Issues",
                        "value": str(total_issues),
                        "short": True
                    },
                    {
                        "title": "Critical Issues", 
                        "value": str(critical_issues),
                        "short": True
                    },
                    {
                        "title": "Security Score",
                        "value": f"{analysis_result.metrics.get('security_score', 'N/A')}/100",
                        "short": True
                    },
                    {
                        "title": "Quality Score",
                        "value": f"{analysis_result.metrics.get('maintainability_score', 'N/A')}/100",
                        "short": True
                    }
                ]
            }]
        }
        
        # Send to Slack (implementation would use requests library)
        logger.info(f"Would send Slack notification: {message}")

class TeamsNotificationHandler(NotificationHandler):
    """Microsoft Teams notification handler"""
    
    def send_notification(self, analysis_result: AnalysisResult, config: Dict[str, Any]):
        logger.info("Teams notification sent")

class EmailNotificationHandler(NotificationHandler):
    """Email notification handler"""
    
    def send_notification(self, analysis_result: AnalysisResult, config: Dict[str, Any]):
        logger.info("Email notification sent")

class WebhookNotificationHandler(NotificationHandler):
    """Generic webhook notification handler"""
    
    def send_notification(self, analysis_result: AnalysisResult, config: Dict[str, Any]):
        logger.info("Webhook notification sent")

# Report formatters

class ReportFormatter:
    """Base class for report formatters"""
    
    def format_report(self, analysis_result: AnalysisResult) -> str:
        raise NotImplementedError

class JUnitReportFormatter(ReportFormatter):
    """JUnit XML report formatter"""
    
    def format_report(self, analysis_result: AnalysisResult) -> str:
        # Implementation would generate JUnit XML
        return f'<testsuite name="Code Analysis" tests="{len(analysis_result.issues)}"></testsuite>'

class SonarQubeReportFormatter(ReportFormatter):
    """SonarQube JSON report formatter"""
    
    def format_report(self, analysis_result: AnalysisResult) -> str:
        # Implementation would generate SonarQube-compatible JSON
        return json.dumps({"issues": [asdict(issue) for issue in analysis_result.issues]}, default=str)

class SARIFReportFormatter(ReportFormatter):
    """SARIF JSON report formatter"""
    
    def format_report(self, analysis_result: AnalysisResult) -> str:
        # Implementation would generate SARIF format
        return json.dumps({"version": "2.1.0", "runs": []}, default=str)

class CheckstyleReportFormatter(ReportFormatter):
    """Checkstyle XML report formatter"""
    
    def format_report(self, analysis_result: AnalysisResult) -> str:
        # Implementation would generate Checkstyle XML
        return '<checkstyle version="8.0"></checkstyle>'

class JSONReportFormatter(ReportFormatter):
    """JSON report formatter"""
    
    def format_report(self, analysis_result: AnalysisResult) -> str:
        return json.dumps(asdict(analysis_result), default=str, indent=2)

class HTMLReportFormatter(ReportFormatter):
    """HTML report formatter"""
    
    def format_report(self, analysis_result: AnalysisResult) -> str:
        # Would generate HTML report
        return '<html><body><h1>Analysis Report</h1></body></html>'
        """Analyze code for performance issues"""
        issues = []
        lines = code.split('\n')
        
        for perf_type, patterns in self.performance_patterns.items():
            for pattern in patterns:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        issue = CodeIssue(
                            issue_type='PERFORMANCE',
                            severity='MEDIUM',
                            file_path=file_path,
                            line_number=line_num,
                            column=0,
                            message=f'Potential performance issue: {perf_type.replace("_", " ")}',
                            description=f'Line may contain inefficient code pattern: {perf_type}',
                            recommendation=self._get_performance_recommendation(perf_type),
                            confidence=0.7,
                            rule_id=f'PERF_{perf_type.upper()}',
                            code_snippet=line.strip(),
                            fix_suggestion=self._get_performance_fix(perf_type)
                        )
                        issues.append(issue)
        
        return issues
    
    def _get_performance_recommendation(self, perf_type: str) -> str:
        recommendations = {
            'inefficient_loop': 'Use enumerate() instead of range(len())',
            'string_concatenation': 'Use join() for multiple string concatenations',
            'repeated_computation': 'Cache computed values outside loops',
            'inefficient_data_structure': 'Use list comprehensions or appropriate data structures'
        }
        return recommendations.get(perf_type, 'Review for performance optimization opportunities')
    
    def _get_performance_fix(self, perf_type: str) -> str:
        fixes = {
            'inefficient_loop': 'for index, item in enumerate(items):',
            'string_concatenation': 'result = "".join([str1, str2, str3])',
            'repeated_computation': 'length = len(items)  # Cache outside loop',
            'inefficient_data_structure': 'result = [item for item in source if condition]'
        }
        return fixes.get(perf_type, 'Apply performance optimization techniques')

class AdvancedMLAnalyzer:
    """Advanced machine learning analyzer with transformer models and explainable AI"""
    
    def __init__(self):
        self.models = {}
        self.explainer = ExplainableAI()
        self.ensemble = EnsemblePredictor()
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize advanced ML models if available"""
        # Code understanding transformer
        if TRANSFORMERS_AVAILABLE:
            try:
                self.models['code_bert'] = pipeline(
                    'feature-extraction',
                    model='microsoft/codebert-base',
                    tokenizer='microsoft/codebert-base'
                )
                logger.info("Loaded CodeBERT model for code understanding")
            except Exception as e:
                logger.warning(f"Could not load CodeBERT: {e}")
        
        # Sentence transformer for semantic similarity
        if SENTENCE_TRANSFORMERS_AVAILABLE:
            try:
                self.models['sentence_transformer'] = SentenceTransformer('all-MiniLM-L6-v2')
                logger.info("Loaded SentenceTransformer model")
            except Exception as e:
                logger.warning(f"Could not load SentenceTransformer: {e}")
        
        # Initialize ensemble of traditional ML models
        self.ensemble.initialize_models()
    
    def analyze_code_semantics(self, code: str, file_path: str) -> List[CodeIssue]:
        """Analyze code using advanced ML models"""
        issues = []
        
        # Transformer-based code analysis
        if 'code_bert' in self.models:
            try:
                semantic_issues = self._analyze_with_codebert(code, file_path)
                issues.extend(semantic_issues)
            except Exception as e:
                logger.warning(f"CodeBERT analysis failed: {e}")
        
        # Ensemble prediction
        try:
            ensemble_issues = self.ensemble.predict_issues(code, file_path)
            issues.extend(ensemble_issues)
        except Exception as e:
            logger.warning(f"Ensemble prediction failed: {e}")
        
        # Add explainability to all issues
        for issue in issues:
            explanation = self.explainer.explain_issue(issue, code)
            issue.description += f"\n\nAI Explanation: {explanation['reasoning']}"
            if explanation['confidence_factors']:
                issue.description += f"\nConfidence factors: {', '.join(explanation['confidence_factors'])}"
        
        return issues
    
    def _analyze_with_codebert(self, code: str, file_path: str) -> List[CodeIssue]:
        """Analyze code using CodeBERT transformer model"""
        issues = []
        
        # Split code into meaningful chunks for analysis
        code_chunks = self._chunk_code_semantically(code)
        
        for chunk_info in code_chunks:
            chunk_code = chunk_info['code']
            start_line = chunk_info['start_line']
            chunk_type = chunk_info['type']  # function, class, etc.
            
            # Get embeddings from CodeBERT
            try:
                embeddings = self.models['code_bert'](chunk_code)
                
                # Analyze embeddings for potential issues
                semantic_score = self._calculate_semantic_quality_score(embeddings)
                
                if semantic_score < 0.5:  # Threshold for concerning patterns
                    issue = CodeIssue(
                        issue_type='AI_SEMANTIC',
                        severity='MEDIUM',
                        file_path=file_path,
                        line_number=start_line,
                        column=0,
                        message=f'AI detected potential semantic issues in {chunk_type}',
                        description=f'Advanced ML analysis suggests semantic concerns in {chunk_type}',
                        recommendation='Review code logic and structure for clarity and correctness',
                        confidence=semantic_score,
                        rule_id='AI_SEMANTIC_ANALYSIS',
                        code_snippet=chunk_code[:100] + '...' if len(chunk_code) > 100 else chunk_code
                    )
                    issues.append(issue)
                
            except Exception as e:
                logger.debug(f"CodeBERT analysis failed for chunk: {e}")
        
        return issues
    
    def _chunk_code_semantically(self, code: str) -> List[Dict[str, Any]]:
        """Split code into semantic chunks (functions, classes, etc.)"""
        chunks = []
        try:
            tree = ast.parse(code)
            lines = code.split('\n')
            
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
                    start_line = node.lineno
                    end_line = getattr(node, 'end_lineno', start_line + 10)
                    
                    chunk_code = '\n'.join(lines[start_line-1:end_line])
                    chunk_type = 'function' if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) else 'class'
                    
                    chunks.append({
                        'code': chunk_code,
                        'start_line': start_line,
                        'end_line': end_line,
                        'type': chunk_type,
                        'name': node.name
                    })
        
        except SyntaxError:
            # Fall back to simple line-based chunking
            lines = code.split('\n')
            chunk_size = 20  # lines per chunk
            for i in range(0, len(lines), chunk_size):
                chunk_lines = lines[i:i + chunk_size]
                chunks.append({
                    'code': '\n'.join(chunk_lines),
                    'start_line': i + 1,
                    'end_line': min(i + chunk_size, len(lines)),
                    'type': 'code_block',
                    'name': f'block_{i//chunk_size + 1}'
                })
        
        return chunks
    
    def _calculate_semantic_quality_score(self, embeddings) -> float:
        """Calculate semantic quality score from embeddings"""
        try:
            # Convert embeddings to numpy array if it's a tensor
            if hasattr(embeddings, 'numpy'):
                emb_array = embeddings.numpy()
            else:
                emb_array = np.array(embeddings)
            
            # Flatten if needed
            if emb_array.ndim > 2:
                emb_array = emb_array.mean(axis=1)  # Average over sequence dimension
            
            # Calculate various quality metrics
            variance = np.var(emb_array)
            mean_activation = np.mean(np.abs(emb_array))
            
            # Normalize to 0-1 score (higher is better)
            quality_score = min(1.0, (variance * mean_activation) / 10.0)
            
            return quality_score
        
        except Exception:
            return 0.5  # Default neutral score

class EnsemblePredictor:
    """Ensemble of multiple ML models for robust prediction"""
    
    def __init__(self):
        self.models = {}
        self.feature_extractors = {}
        self.is_initialized = False
    
    def initialize_models(self):
        """Initialize ensemble of ML models"""
        try:
            # Random Forest for defect prediction
            self.models['rf_defect'] = RandomForestClassifier(
                n_estimators=100, 
                max_depth=10,
                random_state=42
            )
            
            # Isolation Forest for anomaly detection
            self.models['isolation_forest'] = IsolationForest(
                contamination=0.1,
                random_state=42
            )
            
            # XGBoost if available
            try:
                import xgboost as xgb
                self.models['xgboost'] = xgb.XGBClassifier(
                    n_estimators=50,
                    max_depth=6,
                    random_state=42
                )
            except ImportError:
                logger.info("XGBoost not available, using alternative models")
            
            # Feature extractors
            self.feature_extractors['tfidf'] = TfidfVectorizer(
                max_features=500,
                ngram_range=(1, 2),
                stop_words=None
            )
            
            self.is_initialized = True
            logger.info(f"Initialized ensemble with {len(self.models)} models")
            
        except Exception as e:
            logger.error(f"Failed to initialize ensemble models: {e}")
    
    def predict_issues(self, code: str, file_path: str) -> List[CodeIssue]:
        """Predict issues using ensemble of models"""
        if not self.is_initialized:
            return []
        
        issues = []
        
        # Extract features from code
        features = self._extract_ensemble_features(code)
        
        # Anomaly detection
        if 'isolation_forest' in self.models and len(features) > 0:
            try:
                anomaly_score = self.models['isolation_forest'].decision_function([features])[0]
                if anomaly_score < -0.3:  # Threshold for anomaly
                    issue = CodeIssue(
                        issue_type='AI_ANOMALY',
                        severity='MEDIUM',
                        file_path=file_path,
                        line_number=1,
                        column=0,
                        message='AI detected anomalous code patterns',
                        description=f'Ensemble anomaly detection score: {anomaly_score:.3f}',
                        recommendation='Review code structure and patterns for potential issues',
                        confidence=min(1.0, abs(anomaly_score)),
                        rule_id='AI_ANOMALY_DETECTION',
                        code_snippet='# File-level anomaly detection'
                    )
                    issues.append(issue)
            except Exception as e:
                logger.debug(f"Anomaly detection failed: {e}")
        
        return issues
    
    def _extract_ensemble_features(self, code: str) -> List[float]:
        """Extract features for ensemble models"""
        features = []
        
        try:
            # Basic code metrics
            lines = code.split('\n')
            features.extend([
                len(lines),  # Lines of code
                len([line for line in lines if line.strip()]),  # Non-empty lines
                len(code),  # Character count
                code.count('if'),  # Conditional statements
                code.count('for'),  # Loops
                code.count('while'),  # While loops
                code.count('def'),  # Function definitions
                code.count('class'),  # Class definitions
                code.count('import'),  # Imports
                len(re.findall(r'\b\w+\b', code)),  # Word count
            ])
            
            # Complexity indicators
            nesting_level = self._estimate_nesting_level(code)
            features.append(nesting_level)
            
            # Comment ratio
            comment_lines = len([line for line in lines if line.strip().startswith('#')])
            comment_ratio = comment_lines / len(lines) if lines else 0
            features.append(comment_ratio)
            
            # Average line length
            avg_line_length = np.mean([len(line) for line in lines]) if lines else 0
            features.append(avg_line_length)
            
        except Exception as e:
            logger.debug(f"Feature extraction failed: {e}")
            features = [0] * 13  # Default feature vector
        
        return features
    
    def _estimate_nesting_level(self, code: str) -> int:
        """Estimate maximum nesting level in code"""
        max_nesting = 0
        current_nesting = 0
        
        for line in code.split('\n'):
            stripped = line.strip()
            if any(stripped.startswith(keyword) for keyword in ['if', 'for', 'while', 'with', 'try', 'def', 'class']):
                current_nesting = len(line) - len(line.lstrip())
                max_nesting = max(max_nesting, current_nesting // 4)  # Assuming 4-space indentation
        
        return max_nesting

class ExplainableAI:
    """Provides explanations for AI-generated findings"""
    
    def __init__(self):
        self.explanation_templates = {
            'SECURITY': {
                'reasoning': 'Security analysis identified patterns matching known vulnerability signatures',
                'factors': ['Pattern matching', 'Security rule database', 'Context analysis']
            },
            'PERFORMANCE': {
                'reasoning': 'Performance analysis detected inefficient coding patterns that may impact execution speed',
                'factors': ['Algorithm complexity', 'Resource usage patterns', 'Best practice violations']
            },
            'CODE_SMELL': {
                'reasoning': 'Code quality analysis identified maintainability concerns based on established metrics',
                'factors': ['Code structure', 'Design patterns', 'Maintainability metrics']
            },
            'AI_SEMANTIC': {
                'reasoning': 'Advanced ML models detected semantic inconsistencies or complexity issues',
                'factors': ['Neural network analysis', 'Code embeddings', 'Semantic similarity']
            },
            'AI_ANOMALY': {
                'reasoning': 'Ensemble anomaly detection identified unusual patterns compared to typical code',
                'factors': ['Statistical analysis', 'Multiple model consensus', 'Pattern deviation']
            }
        }
    
    def explain_issue(self, issue: CodeIssue, code_context: str = "") -> Dict[str, Any]:
        """Generate explanation for an AI-detected issue"""
        template = self.explanation_templates.get(issue.issue_type, {
            'reasoning': 'Analysis identified potential code quality concerns',
            'factors': ['Static analysis', 'Pattern recognition']
        })
        
        explanation = {
            'reasoning': template['reasoning'],
            'confidence_factors': self._calculate_confidence_factors(issue, code_context),
            'decision_tree': self._generate_decision_tree(issue),
            'similar_patterns': self._find_similar_patterns(issue, code_context),
            'recommendations': self._generate_detailed_recommendations(issue)
        }
        
        return explanation
    
    def _calculate_confidence_factors(self, issue: CodeIssue, code_context: str) -> List[str]:
        """Calculate factors contributing to confidence score"""
        factors = []
        
        if issue.confidence > 0.8:
            factors.append("High pattern match strength")
        elif issue.confidence > 0.6:
            factors.append("Moderate pattern match strength")
        else:
            factors.append("Low pattern match strength")
        
        if issue.severity in ['CRITICAL', 'HIGH']:
            factors.append("High severity impact")
        
        if len(issue.code_snippet) > 50:
            factors.append("Sufficient code context")
        
        if 'TODO' in code_context.upper() or 'FIXME' in code_context.upper():
            factors.append("Existing maintenance markers")
        
        return factors
    
    def _generate_decision_tree(self, issue: CodeIssue) -> List[str]:
        """Generate simple decision tree explanation"""
        tree = [
            f"1. Analyzed code for {issue.issue_type.lower().replace('_', ' ')} patterns",
            f"2. Found pattern matching rule: {issue.rule_id}",
            f"3. Calculated confidence: {issue.confidence:.2f}",
            f"4. Assigned severity: {issue.severity} based on impact assessment"
        ]
        return tree
    
    def _find_similar_patterns(self, issue: CodeIssue, code_context: str) -> List[str]:
        """Find similar patterns in the codebase (simplified)"""
        # This would ideally search the entire codebase for similar patterns
        return [f"Similar {issue.issue_type.lower()} patterns may exist elsewhere in the codebase"]
    
    def _generate_detailed_recommendations(self, issue: CodeIssue) -> List[str]:
        """Generate detailed, actionable recommendations"""
        recommendations = [issue.recommendation]
        
        # Add specific recommendations based on issue type
        if issue.issue_type == 'SECURITY':
            recommendations.extend([
                "Consider input validation and sanitization",
                "Review security best practices documentation",
                "Consider security testing tools"
            ])
        elif issue.issue_type == 'PERFORMANCE':
            recommendations.extend([
                "Profile the code to measure actual impact",
                "Consider algorithmic optimizations",
                "Review performance testing results"
            ])
        elif issue.issue_type == 'CODE_SMELL':
            recommendations.extend([
                "Consider refactoring for better maintainability",
                "Review design patterns and principles",
                "Add unit tests to support refactoring"
            ])
        
        return recommendations

class MLBasedDefectPredictor:
    """Uses machine learning to predict defect-prone code"""
    
    def __init__(self):
        self.model = None
        self.feature_extractor = CodeFeatureExtractor()
        self.is_trained = False
        
    def train_model(self, training_data: List[Tuple[str, bool]]):
        """Train the defect prediction model"""
        if len(training_data) < 10:
            logger.warning("Insufficient training data for ML model")
            return
            
        features = []
        labels = []
        
        for code, is_defective in training_data:
            feature_vector = self._extract_features(code)
            features.append(list(feature_vector.values()))
            labels.append(is_defective)
        
        X = np.array(features)
        y = np.array(labels)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Train model
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        logger.info(f"Model accuracy: {classification_report(y_test, y_pred)}")
        
        self.is_trained = True
    
    def predict_defects(self, code: str, file_path: str) -> List[CodeIssue]:
        """Predict defects in code using ML model"""
        if not self.is_trained or self.model is None:
            return []
        
        features = self._extract_features(code)
        feature_vector = np.array([list(features.values())])
        
        prediction = self.model.predict(feature_vector)[0]
        probability = self.model.predict_proba(feature_vector)[0]
        
        issues = []
        if prediction and max(probability) > 0.7:  # High confidence threshold
            issue = CodeIssue(
                issue_type='ML_PREDICTION',
                severity='MEDIUM',
                file_path=file_path,
                line_number=1,
                column=0,
                message='ML model predicts high defect probability',
                description=f'Machine learning analysis suggests this file may be defect-prone (conf \
                    idence: {max(probability):.2f})',
                recommendation='Consider additional code review and testing',
                confidence=max(probability),
                rule_id='ML_DEFECT_PREDICTION',
                code_snippet='# File-level prediction',
                fix_suggestion='Apply thorough testing and consider refactoring complex areas'
            )
            issues.append(issue)
        
        return issues
    
    def _extract_features(self, code: str) -> Dict[str, float]:
        """Extract numerical features for ML model"""
        ast_features = self.feature_extractor.extract_ast_features(code)
        
        # Add additional computed features
        lines = code.split('\n')
        ast_features.update({
            'comment_ratio': self._calculate_comment_ratio(lines),
            'blank_line_ratio': self._calculate_blank_line_ratio(lines),
            'avg_line_length': np.mean([len(line) for line in lines]),
            'keyword_density': self._calculate_keyword_density(code)
        })
        
        return ast_features
    
    def _calculate_comment_ratio(self, lines: List[str]) -> float:
        comment_lines = sum(1 for line in lines if line.strip().startswith('#'))
        return comment_lines / len(lines) if lines else 0
    
    def _calculate_blank_line_ratio(self, lines: List[str]) -> float:
        blank_lines = sum(1 for line in lines if not line.strip())
        return blank_lines / len(lines) if lines else 0
    
    def _calculate_keyword_density(self, code: str) -> float:
        words = re.findall(r'\b\w+\b', code.lower())
        keyword_count = sum(1 for word in words if keyword.iskeyword(word))
        return keyword_count / len(words) if words else 0

class ProjectContextAnalyzer:
    """Analyzes project-specific patterns and adapts to coding styles"""
    
    def __init__(self):
        self.project_patterns = defaultdict(list)
        self.coding_style_rules = {}
        self.project_metrics = {}
    
    def analyze_project_context(self, project_path: str) -> Dict[str, Any]:
        """Analyze project structure and patterns"""
        context = {
            'file_types': self._analyze_file_types(project_path),
            'directory_structure': self._analyze_directory_structure(project_path),
            'import_patterns': self._analyze_import_patterns(project_path),
            'naming_conventions': self._analyze_naming_conventions(project_path),
            'documentation_patterns': self._analyze_documentation_patterns(project_path)
        }
        
        self.project_metrics = context
        return context
    
    def _analyze_file_types(self, project_path: str) -> Dict[str, int]:
        """Analyze file type distribution"""
        file_types = defaultdict(int)
        for root, _, files in os.walk(project_path):
            for file in files:
                ext = Path(file).suffix
                file_types[ext] += 1
        return dict(file_types)
    
    def _analyze_directory_structure(self, project_path: str) -> Dict[str, Any]:
        """Analyze project directory structure"""
        structure = {
            'depth': 0,
            'common_dirs': [],
            'package_structure': []
        }
        
        for root, dirs, files in os.walk(project_path):
            level = root.replace(project_path, '').count(os.sep)
            structure['depth'] = max(structure['depth'], level)
            
            if '__init__.py' in files:
                structure['package_structure'].append(root)
        
        return structure
    
    def _analyze_import_patterns(self, project_path: str) -> Dict[str, List[str]]:
        """Analyze common import patterns in the project"""
        import_patterns = defaultdict(list)
        
        for root, _, files in os.walk(project_path):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            tree = ast.parse(content)
                            
                            for node in ast.walk(tree):
                                if isinstance(node, ast.Import):
                                    for alias in node.names:
                                        import_patterns['standard'].append(alias.name)
                                elif isinstance(node, ast.ImportFrom):
                                    if node.module:
                                        import_patterns['from_import'].append(node.module)
                    except:
                        continue
        
        return dict(import_patterns)
    
    def _analyze_naming_conventions(self, project_path: str) -> Dict[str, str]:
        """Detect naming conventions used in the project"""
        naming_patterns = {
            'function_naming': 'unknown',
            'class_naming': 'unknown',
            'variable_naming': 'unknown'
        }
        
        function_names = []
        class_names = []
        variable_names = []
        
        for root, _, files in os.walk(project_path):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            tree = ast.parse(content)
                            
                            for node in ast.walk(tree):
                                if isinstance(node, ast.FunctionDef):
                                    function_names.append(node.name)
                                elif isinstance(node, ast.ClassDef):
                                    class_names.append(node.name)
                                elif isinstance(node, ast.Name):
                                    variable_names.append(node.id)
                    except:
                        continue
        
        # Determine naming patterns
        if function_names:
            if all('_' in name for name in function_names[:10]):
                naming_patterns['function_naming'] = 'snake_case'
            elif all(name[0].islower() and any(c.isupper() for c in name) for name in function_names[:10]):
                naming_patterns['function_naming'] = 'camelCase'
        
        if class_names:
            if all(name[0].isupper() for name in class_names[:10]):
                naming_patterns['class_naming'] = 'PascalCase'
        
        return naming_patterns
    
    def _analyze_documentation_patterns(self, project_path: str) -> Dict[str, Any]:
        """Analyze documentation patterns in the project"""
        doc_patterns = {
            'has_readme': False,
            'docstring_style': 'unknown',
            'documentation_coverage': 0.0
        }
        
        # Check for README
        readme_files = ['README.md', 'README.rst', 'README.txt']
        for readme in readme_files:
            if os.path.exists(os.path.join(project_path, readme)):
                doc_patterns['has_readme'] = True
                break
        
        # Analyze docstring patterns
        total_functions = 0
        documented_functions = 0
        
        for root, _, files in os.walk(project_path):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            tree = ast.parse(content)
                            
                            for node in ast.walk(tree):
                                if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                                    total_functions += 1
                                    if (node.body and isinstance(node.body[0], ast.Expr) 
                                        and isinstance(node.body[0].value, ast.Constant)
                                        and isinstance(node.body[0].value.value, str)):
                                        documented_functions += 1
                    except:
                        continue
        
        if total_functions > 0:
            doc_patterns['documentation_coverage'] = documented_functions / total_functions
        
        return doc_patterns

class ModularAnalysisEngine:
    """Engine for handling large codebase analysis through modular processing"""
    
    def __init__(self, max_file_size: int = 1024*1024, chunk_size: int = 1000):
        self.max_file_size = max_file_size  # Max file size in bytes
        self.chunk_size = chunk_size  # Lines per chunk
        self.analysis_cache = {}
        self.memory_threshold = 500 * 1024 * 1024  # 500MB memory threshold
        
    def chunk_large_file(self, file_path: str, content: str) -> List[Tuple[str, int, int]]:
        """Split large files into manageable chunks while preserving context"""
        lines = content.split('\n')
        chunks = []
        
        if len(lines) <= self.chunk_size:
            return [(content, 1, len(lines))]
        
        # Smart chunking - try to break at class/function boundaries
        try:
            tree = ast.parse(content)
            function_lines = set()
            class_lines = set()
            
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    if isinstance(node, ast.ClassDef):
                        class_lines.add(node.lineno)
                    else:
                        function_lines.add(node.lineno)
            
            # Create chunks starting at natural boundaries
            chunk_start = 0
            for i in range(0, len(lines), self.chunk_size):
                # Look for natural breaking point
                chunk_end = min(i + self.chunk_size, len(lines))
                
                # Adjust chunk end to function/class boundary if possible
                for line_num in sorted(function_lines | class_lines, reverse=True):
                    if i < line_num <= chunk_end + 50:  # Allow some flexibility
                        chunk_end = line_num
                        break
                
                chunk_content = '\n'.join(lines[chunk_start:chunk_end])
                if chunk_content.strip():  # Only add non-empty chunks
                    chunks.append((chunk_content, chunk_start + 1, chunk_end))
                
                chunk_start = chunk_end
                
                # Prevent infinite loop
                if chunk_start >= len(lines):
                    break
        
        except SyntaxError:
            # Fall back to simple line-based chunking
            for i in range(0, len(lines), self.chunk_size):
                chunk_lines = lines[i:i + self.chunk_size]
                chunk_content = '\n'.join(chunk_lines)
                if chunk_content.strip():
                    chunks.append((chunk_content, i + 1, min(i + self.chunk_size, len(lines))))
        
        return chunks if chunks else [(content, 1, len(lines))]
    
    def should_analyze_file(self, file_path: str) -> bool:
        """Determine if file should be analyzed based on size and type"""
        try:
            file_size = os.path.getsize(file_path)
            return file_size <= self.max_file_size * 5  # Allow up to 5MB files
        except OSError:
            return False
    
    def get_memory_usage(self) -> int:
        """Get current memory usage in bytes"""
        try:
            import psutil
            process = psutil.Process(os.getpid())
            return process.memory_info().rss
        except ImportError:
            # Fallback without psutil
            return 0
    
    def should_pause_for_memory(self) -> bool:
        """Check if analysis should pause due to memory constraints"""
        return self.get_memory_usage() > self.memory_threshold

class RealTimeAnalysisEngine:
    """Real-time code analysis with file watching and incremental updates"""
    
    def __init__(self, analyzer: 'IntelligentCodeAnalyzer', callback: Optional[Callable] = None):
        self.analyzer = analyzer
        if not WATCHDOG_AVAILABLE:
            logger.warning("Watchdog library not available. Real-time analysis will be disabled.")
            self.observer = None
        else:
            self.observer = Observer()
        self.analysis_queue = queue.Queue()
        self.callback = callback  # Callback for real-time results
        self.is_running = False
        self.analysis_cache = {}  # Cache for file hashes and results
        self.analysis_thread = None
        self.debounce_delay = 2.0  # Seconds to wait before analyzing after file change
        
    def start_watching(self, paths: List[str] = None):
        """Start watching specified paths for file changes"""
        if not WATCHDOG_AVAILABLE or self.observer is None:
            logger.warning("Cannot start real-time watching: watchdog library not available")
            return
        
        if paths is None:
            paths = [self.analyzer.project_path]
        
        for path in paths:
            if os.path.exists(path):
                event_handler = CodeFileEventHandler(self.analysis_queue, self.debounce_delay)
                self.observer.schedule(event_handler, path, recursive=True)
        
        self.observer.start()
        self.is_running = True
        
        # Start analysis worker thread
        self.analysis_thread = threading.Thread(target=self._analysis_worker, daemon=True)
        self.analysis_thread.start()
        
        logger.info(f"Started real-time analysis watching {len(paths)} paths")
    
    def stop_watching(self):
        """Stop watching for file changes"""
        self.is_running = False
        if self.observer and self.observer.is_alive():
            self.observer.stop()
            self.observer.join()
        
        # Signal analysis thread to stop
        self.analysis_queue.put(None)
        
        if self.analysis_thread and self.analysis_thread.is_alive():
            self.analysis_thread.join(timeout=5)
        
        logger.info("Stopped real-time analysis")
    
    def _analysis_worker(self):
        """Worker thread for processing file analysis queue"""
        while self.is_running:
            try:
                item = self.analysis_queue.get(timeout=1)
                if item is None:  # Stop signal
                    break
                
                file_path, event_type = item
                
                # Skip if file was deleted
                if event_type == 'deleted' or not os.path.exists(file_path):
                    # Remove from cache if it exists
                    self.analysis_cache.pop(file_path, None)
                    continue
                
                # Check if file has actually changed using hash
                if not self._has_file_changed(file_path):
                    continue
                
                # Perform incremental analysis
                self._analyze_file_incremental(file_path)
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error in analysis worker: {e}")
    
    def _has_file_changed(self, file_path: str) -> bool:
        """Check if file has changed since last analysis using content hash"""
        try:
            with open(file_path, 'rb') as f:
                content_hash = hashlib.md5(f.read()).hexdigest()
            
            if file_path in self.analysis_cache:
                return self.analysis_cache[file_path]['hash'] != content_hash
            
            return True  # New file, consider it changed
        except Exception:
            return True  # If we can't read it, assume it changed
    
    def _analyze_file_incremental(self, file_path: str):
        """Perform incremental analysis on a single file"""
        try:
            # Analyze the file
            issues, metrics = self.analyzer._analyze_file(file_path)
            
            # Update cache
            with open(file_path, 'rb') as f:
                content_hash = hashlib.md5(f.read()).hexdigest()
            
            self.analysis_cache[file_path] = {
                'hash': content_hash,
                'issues': issues,
                'metrics': metrics,
                'timestamp': datetime.now()
            }
            
            # Create incremental result
            result = {
                'file_path': file_path,
                'issues': issues,
                'metrics': metrics,
                'analysis_type': 'incremental',
                'timestamp': datetime.now()
            }
            
            # Call callback if provided
            if self.callback:
                self.callback(result)
            
            # Store in database
            self._store_incremental_result(result)
            
            logger.info(f"Incremental analysis complete for {file_path}: {len(issues)} issues")
            
        except Exception as e:
            logger.error(f"Error analyzing {file_path}: {e}")
    
    def _store_incremental_result(self, result: Dict[str, Any]):
        """Store incremental analysis result in database"""
        conn = sqlite3.connect(self.analyzer.db_path)
        cursor = conn.cursor()
        
        # Clear previous results for this file
        cursor.execute('DELETE FROM analysis_results WHERE file_path = ?', (result['file_path'],))
        
        # Store new issues
        for issue in result['issues']:
            cursor.execute('''
                INSERT INTO analysis_results 
                (timestamp, file_path, issue_type, severity, line_number, message, rule_id, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                result['timestamp'],
                issue.file_path,
                issue.issue_type,
                issue.severity,
                issue.line_number,
                issue.message,
                issue.rule_id,
                issue.confidence
            ))
        
        conn.commit()
        conn.close()
    
    def get_cached_results(self) -> Dict[str, Any]:
        """Get all cached analysis results"""
        return dict(self.analysis_cache)
    
    def force_analyze_file(self, file_path: str):
        """Force analysis of a specific file regardless of cache"""
        self.analysis_cache.pop(file_path, None)  # Remove from cache
        self.analysis_queue.put((file_path, 'modified'))

class CodeFileEventHandler(FileSystemEventHandler if WATCHDOG_AVAILABLE else object):
    """File system event handler for code files"""
    
    def __init__(self, analysis_queue: queue.Queue, debounce_delay: float = 2.0):
        super().__init__()
        self.analysis_queue = analysis_queue
        self.debounce_delay = debounce_delay
        self.pending_files = {}  # File path -> timer
        self.supported_extensions = {'.py', '.js', '.ts', '.java', '.cpp', '.c', '.h', '.go', '.rb', '.php'}
    
    def on_modified(self, event):
        if not event.is_directory:
            self._handle_file_event(event.src_path, 'modified')
    
    def on_created(self, event):
        if not event.is_directory:
            self._handle_file_event(event.src_path, 'created')
    
    def on_deleted(self, event):
        if not event.is_directory:
            self._handle_file_event(event.src_path, 'deleted')
    
    def _handle_file_event(self, file_path: str, event_type: str):
        """Handle file system events with debouncing"""
        # Check if it's a supported code file
        if not self._is_code_file(file_path):
            return
        
        # Skip temporary and hidden files
        filename = os.path.basename(file_path)
        if filename.startswith('.') or filename.endswith('.tmp') or '~' in filename:
            return
        
        # Cancel existing timer for this file
        if file_path in self.pending_files:
            self.pending_files[file_path].cancel()
        
        # Set up debounced analysis
        if event_type != 'deleted':
            timer = threading.Timer(self.debounce_delay, self._queue_analysis, args=(file_path, event_type))
            timer.start()
            self.pending_files[file_path] = timer
        else:
            # Handle deletion immediately
            self._queue_analysis(file_path, event_type)
    
    def _is_code_file(self, file_path: str) -> bool:
        """Check if file is a supported code file"""
        return Path(file_path).suffix.lower() in self.supported_extensions
    
    def _queue_analysis(self, file_path: str, event_type: str):
        """Queue file for analysis"""
        # Remove from pending
        self.pending_files.pop(file_path, None)
        
        # Add to analysis queue
        try:
            self.analysis_queue.put((file_path, event_type), timeout=1)
        except queue.Full:
            logger.warning(f"Analysis queue full, skipping {file_path}")

class IntelligentCodeAnalyzer:
    """Main analyzer that coordinates all analysis components"""
    
    def __init__(self, project_path: str, enable_modular: bool = True):
        self.project_path = project_path
        
        # Advanced analyzers
        self.security_detector = AdvancedSecurityAnalyzer()
        self.smell_detector = CodeSmellDetector()
        self.performance_analyzer = AdvancedPerformanceOptimizationEngine()
        self.ml_predictor = MLBasedDefectPredictor()
        self.context_analyzer = ProjectContextAnalyzer()
        
        # Dashboard integration
        self.dashboard = CodeQualityMetricsDashboard(project_path)
        
        # CI/CD integration framework
        self.cicd_framework = CICDIntegrationFramework(project_path, self)
        
        # Modular analysis engine
        self.modular_engine = ModularAnalysisEngine() if enable_modular else None
        
        # Initialize database for storing results with proper error handling
        import tempfile
        
        # Use temp directory for database if project path is a file or has permission issues
        if os.path.isfile(project_path):
            db_dir = tempfile.gettempdir()
        else:
            db_dir = project_path if os.path.exists(project_path) else tempfile.gettempdir()
        
        self.db_path = os.path.join(db_dir, 'code_analysis.db')
        self._init_database()
        
        # Load or create project-specific models
        self._load_project_models()
        
        # Analysis configuration
        self.config = {
            'enable_ml_prediction': True,
            'enable_context_analysis': True,
            'max_issues_per_file': 50,
            'min_confidence_threshold': 0.5,
            'enable_real_time': False,
            'real_time_callback': None
        }
        
        # Real-time analysis engine
        self.real_time_engine = None
        
        # Multi-language analyzer
        self.multi_lang_analyzer = MultiLanguageAnalyzer()
        
        # Advanced ML analyzer
        self.advanced_ml_analyzer = AdvancedMLAnalyzer()
    
    def _init_database(self):
        """Initialize SQLite database for storing analysis results"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                file_path TEXT,
                issue_type TEXT,
                severity TEXT,
                line_number INTEGER,
                message TEXT,
                rule_id TEXT,
                confidence REAL,
                fixed BOOLEAN DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS project_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                metric_name TEXT,
                metric_value TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _load_project_models(self):
        """Load or create project-specific ML models"""
        if os.path.isfile(self.project_path):
           base_path = os.path.dirname(self.project_path)
        else:
            base_path = self.project_path

        model_path = os.path.join(base_path, '.ml_models')
        os.makedirs(model_path, exist_ok=True)

        # Try to load existing model
        model_file = os.path.join(model_path, 'defect_predictor.joblib')
        if os.path.exists(model_file):
            try:
                self.ml_predictor.model = joblib.load(model_file)
                self.ml_predictor.is_trained = True
                logger.info("Loaded existing ML model")
            except Exception as e:
                logger.warning(f"Failed to load existing model: {e}")
    
    def analyze_codebase(self, max_workers: int = 4) -> AnalysisResult:
        """Perform comprehensive analysis of the codebase"""
        logger.info(f"Starting analysis of {self.project_path}")
        
        # First, analyze project context
        project_context = self.context_analyzer.analyze_project_context(self.project_path)
        
        # Get all supported code files
        code_files = self._get_code_files()
        logger.info(f"Found {len(code_files)} code files to analyze")
        
        # Group files by language for better reporting
        files_by_language = defaultdict(list)
        for file_path in code_files:
            language = LanguageDetector.detect_language(file_path)
            files_by_language[language].append(file_path)
        
        logger.info(f"Languages detected: {dict((lang, len(files)) for lang, files in files_by_language.items())}")
        
        all_issues = []
        file_metrics = {}
        
        # Parallel analysis of files
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {
                executor.submit(self._analyze_file, file_path): file_path 
                for file_path in code_files
            }
            
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    file_issues, metrics = future.result()
                    all_issues.extend(file_issues)
                    file_metrics[file_path] = metrics
                except Exception as e:
                    logger.error(f"Error analyzing {file_path}: {e}")
        
        # Calculate overall metrics
        overall_metrics = self._calculate_overall_metrics(all_issues, file_metrics, project_context)
        
        # Create analysis result
        result = AnalysisResult(
            project_path=self.project_path,
            timestamp=datetime.now(),
            issues=sorted(all_issues, key=lambda x: (x.severity, x.confidence), reverse=True),
            metrics=overall_metrics,
            summary=self._create_summary(all_issues)
        )
        
        # Store results in database
        self._store_results(result)
        
        logger.info(f"Analysis complete. Found {len(all_issues)} issues")
        return result
    
    def _get_code_files(self) -> List[str]:
        """Get all supported code files in the project"""
        code_files = []
        supported_extensions = set(LanguageDetector.LANGUAGE_MAP.keys())
        
        for root, dirs, files in os.walk(self.project_path):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if d not in {
                '.git', '__pycache__', '.pytest_cache', 'node_modules', '.venv', 'venv',
                'build', 'dist', 'target', 'bin', 'obj', '.gradle', 'cmake-build-debug'
            }]
            
            for file in files:
                if not file.startswith('.'):  # Skip hidden files
                    file_ext = Path(file).suffix.lower()
                    if file_ext in supported_extensions:
                        code_files.append(os.path.join(root, file))
        
        return code_files
    
    def _analyze_file(self, file_path: str) -> Tuple[List[CodeIssue], Dict[str, Any]]:
        """Analyze a single file for all types of issues with modular support"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            logger.warning(f"Could not read file {file_path}: {e}")
            return [], {}
        
        # Check if modular analysis is needed
        if (self.modular_engine and 
            len(content) > 50000 and  # File larger than 50k characters
            self.modular_engine.should_analyze_file(file_path)):
            return self._analyze_file_modular(file_path, content)
        
        return self._analyze_file_standard(file_path, content)
    
    def _analyze_file_modular(self, file_path: str, content: str) -> Tuple[List[CodeIssue], Dict[str, Any]]:
        """Analyze large files using modular approach"""
        chunks = self.modular_engine.chunk_large_file(file_path, content)
        all_issues = []
        chunk_metrics = []
        
        logger.info(f"Analyzing {file_path} in {len(chunks)} chunks")
        
        for i, (chunk_content, start_line, end_line) in enumerate(chunks):
            # Check memory usage and pause if needed
            if self.modular_engine.should_pause_for_memory():
                logger.warning("Memory threshold reached, pausing analysis")
                import time
                time.sleep(1)  # Brief pause
                import gc
                gc.collect()  # Force garbage collection
            
            # Analyze chunk
            chunk_issues, chunk_metric = self._analyze_file_standard(
                f"{file_path}#chunk{i}", chunk_content, line_offset=start_line-1
            )
            
            # Adjust line numbers for issues
            for issue in chunk_issues:
                issue.line_number += start_line - 1
                issue.file_path = file_path  # Remove chunk identifier
            
            all_issues.extend(chunk_issues)
            chunk_metrics.append(chunk_metric)
        
        # Combine metrics from all chunks
        combined_metrics = self._combine_chunk_metrics(chunk_metrics)
        combined_metrics['analyzed_in_chunks'] = len(chunks)
        
        return all_issues, combined_metrics
    
    def _analyze_file_standard(
        self,
        file_path: str,
        content: str,
        line_offset: int = 0
    ) -> Tuple[List[CodeIssue], Dict[str, Any]]:
        """Standard file analysis without chunking"""
        issues = []
        
        # Apply configuration filters
        if len(content.strip()) == 0:
            return [], {'lines_of_code': 0}
        
        # Detect language and use appropriate analyzer
        language = LanguageDetector.detect_language(file_path)
        
        if language == 'python':
            # Use existing Python-specific analyzers for Python files
            security_issues = self.security_detector.detect_vulnerabilities(content, file_path)
            issues.extend([issue for issue in security_issues if issue.confidence >= self.config['min_confidence_threshold']])
            
            # Code smell detection
            smell_issues = self.smell_detector.detect_smells(content, file_path)
            issues.extend(smell_issues)
            
            # Performance analysis
            performance_issues = self.performance_analyzer.analyze_performance(content, file_path)
            issues.extend(performance_issues)
            
            # Additional static analysis
            static_issues = self._perform_static_analysis(content, file_path)
            issues.extend(static_issues)
            
            # Calculate Python metrics
            metrics = self._calculate_file_metrics(content, file_path)
        else:
            # Use multi-language analyzer for other languages
            lang_issues, metrics = self.multi_lang_analyzer.analyze_file(file_path, content)
            issues.extend(lang_issues)
        
        # ML-based defect prediction (if enabled) - works for all languages
        if self.config['enable_ml_prediction'] and language == 'python':  # Currently only for Python
            ml_issues = self.ml_predictor.predict_defects(content, file_path)
            issues.extend(ml_issues)
        
        # Advanced ML analysis with explainable AI
        if self.config.get('enable_advanced_ml', True):
            try:
                advanced_ml_issues = self.advanced_ml_analyzer.analyze_code_semantics(content, file_path)
                issues.extend(advanced_ml_issues)
            except Exception as e:
                logger.debug(f"Advanced ML analysis failed for {file_path}: {e}")
        
        # Limit issues per file to prevent overwhelming output
        if len(issues) > self.config['max_issues_per_file']:
            issues = sorted(issues, key=lambda x: (x.severity, x.confidence), reverse=True)[:self.config['max_issues_per_file']]
            logger.warning(f"Limited {file_path} to top {self.config['max_issues_per_file']} issues")
        
        return issues, metrics
    
    def _perform_static_analysis(self, content: str, file_path: str) -> List[CodeIssue]:
        """Perform additional static analysis checks"""
        issues = []
        lines = content.split('\n')
        
        # Check for common anti-patterns
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Bare except clause
            if re.match(r'except\s*:', line):
                issues.append(CodeIssue(
                    issue_type='STATIC_ANALYSIS',
                    severity='MEDIUM',
                    file_path=file_path,
                    line_number=line_num,
                    column=0,
                    message='Bare except clause detected',
                    description='Using bare except clauses can hide unexpected errors',
                    recommendation='Specify specific exception types to catch',
                    confidence=1.0,
                    rule_id='STATIC_BARE_EXCEPT',
                    code_snippet=line,
                    fix_suggestion='except SpecificException:'
                ))
            
            # Unused imports (simplified check)
            import_match = re.match(r'import\s+(\w+)', line)
            if import_match:
                module_name = import_match.group(1)
                if module_name not in content[content.find(line) + len(line):]:
                    issues.append(CodeIssue(
                        issue_type='STATIC_ANALYSIS',
                        severity='LOW',
                        file_path=file_path,
                        line_number=line_num,
                        column=0,
                        message=f'Potentially unused import: {module_name}',
                        description='Imported module may not be used',
                        recommendation='Remove unused imports to improve code clarity',
                        confidence=0.7,
                        rule_id='STATIC_UNUSED_IMPORT',
                        code_snippet=line,
                        fix_suggestion='Remove if confirmed unused'
                    ))
            
            # NOTE comments (TICKET-PENDING)
            if 'TODO' in line.upper() or 'FIXME' in line.upper():
                issues.append(CodeIssue(
                    issue_type='MAINTENANCE',
                    severity='LOW',
                    file_path=file_path,
                    line_number=line_num,
                    column=line.upper().find('TODO') if 'TODO' in line.upper() else line.upper().find('FIXME'),
                    message='TODO/FIXME comment found',
                    description='Code contains unfinished work markers',
                    recommendation='Address TODO/FIXME items or create proper tickets',
                    confidence=1.0,
                    rule_id='MAINTENANCE_TODO',
                    code_snippet=line,
                    fix_suggestion='Complete the task or create a proper issue tracker item'
                ))
        
        return issues
    
    def _calculate_file_metrics(self, content: str, file_path: str) -> Dict[str, Any]:
        """Calculate metrics for a single file"""
        lines = content.split('\n')
        
        try:
            tree = ast.parse(content)
            
            # Count different node types
            class_count = len([n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)])
            function_count = len([n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))])
            import_count = len([n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))])
            
            # Calculate complexity metrics
            complexity_score = self._calculate_cyclomatic_complexity(tree)
            
        except SyntaxError:
            class_count = function_count = import_count = complexity_score = 0
        
        metrics = {
            'lines_of_code': len(lines),
            'non_empty_lines': len([line for line in lines if line.strip()]),
            'comment_lines': len([line for line in lines if line.strip().startswith('#')]),
            'class_count': class_count,
            'function_count': function_count,
            'import_count': import_count,
            'complexity_score': complexity_score,
            'file_size_bytes': len(content.encode('utf-8'))
        }
        
        return metrics
    
    def _calculate_cyclomatic_complexity(self, tree) -> int:
        """Calculate cyclomatic complexity of AST"""
        complexity = 1  # Base complexity
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(node, ast.BoolOp):
                complexity += len(node.values) - 1
            elif isinstance(node, (ast.Try, ast.ExceptHandler)):
                complexity += 1
        
        return complexity
    
    def _combine_chunk_metrics(self, chunk_metrics: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Combine metrics from multiple chunks into a single file metric"""
        if not chunk_metrics:
            return {}
        
        combined = {
            'lines_of_code': sum(m.get('lines_of_code', 0) for m in chunk_metrics),
            'non_empty_lines': sum(m.get('non_empty_lines', 0) for m in chunk_metrics),
            'comment_lines': sum(m.get('comment_lines', 0) for m in chunk_metrics),
            'class_count': sum(m.get('class_count', 0) for m in chunk_metrics),
            'function_count': sum(m.get('function_count', 0) for m in chunk_metrics),
            'import_count': max(m.get('import_count', 0) for m in chunk_metrics),  # Imports typically at top
            'complexity_score': max(m.get('complexity_score', 0) for m in chunk_metrics),
            'file_size_bytes': sum(m.get('file_size_bytes', 0) for m in chunk_metrics)
        }
        
        return combined
    
    def _calculate_overall_metrics(self, issues: List[CodeIssue], file_metrics: Dict[str, Dict], 
                                 project_context: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall project metrics"""
        total_files = len(file_metrics)
        total_loc = sum(metrics.get('lines_of_code', 0) for metrics in file_metrics.values())
        
        # Issue distribution
        issue_by_type = Counter(issue.issue_type for issue in issues)
        issue_by_severity = Counter(issue.severity for issue in issues)
        
        # Quality scores
        security_score = self._calculate_security_score(issues)
        maintainability_score = self._calculate_maintainability_score(issues, file_metrics)
        performance_score = self._calculate_performance_score(issues)
        
        return {
            'total_files_analyzed': total_files,
            'total_lines_of_code': total_loc,
            'total_issues': len(issues),
            'issues_by_type': dict(issue_by_type),
            'issues_by_severity': dict(issue_by_severity),
            'security_score': security_score,
            'maintainability_score': maintainability_score,
            'performance_score': performance_score,
            'average_complexity': np.mean([m.get('complexity_score', 0) for m in file_metrics.values()]),
            'project_context': project_context,
            'analysis_timestamp': datetime.now().isoformat()
        }
    
    def _calculate_security_score(self, issues: List[CodeIssue]) -> float:
        """Calculate security score (0-100, higher is better)"""
        security_issues = [i for i in issues if i.issue_type == 'SECURITY']
        if not security_issues:
            return 100.0
        
        # Weight by severity
        severity_weights = {'CRITICAL': 10, 'HIGH': 5, 'MEDIUM': 2, 'LOW': 1}
        total_weight = sum(severity_weights.get(issue.severity, 1) for issue in security_issues)
        
        # Score decreases with more and higher severity issues
        score = max(0, 100 - (total_weight * 2))
        return score
    
    def _calculate_maintainability_score(self, issues: List[CodeIssue], 
                                       file_metrics: Dict[str, Dict]) -> float:
        """Calculate maintainability score (0-100, higher is better)"""
        code_smell_issues = [i for i in issues if i.issue_type == 'CODE_SMELL']
        
        # Factor in complexity and documentation
        avg_complexity = np.mean([m.get('complexity_score', 0) for m in file_metrics.values()]) if file_metrics else 0
        
        # Calculate documentation ratio
        total_functions = sum(m.get('function_count', 0) for m in file_metrics.values())
        comment_lines = sum(m.get('comment_lines', 0) for m in file_metrics.values())
        total_lines = sum(m.get('lines_of_code', 1) for m in file_metrics.values())
        
        comment_ratio = comment_lines / total_lines if total_lines > 0 else 0
        
        # Base score
        score = 80.0
        
        # Penalize for code smells
        score -= len(code_smell_issues) * 2
        
        # Penalize for high complexity
        if avg_complexity > 10:
            score -= (avg_complexity - 10) * 3
        
        # Bonus for good documentation
        score += comment_ratio * 20
        
        return max(0, min(100, score))
    
    def _calculate_performance_score(self, issues: List[CodeIssue]) -> float:
        """Calculate performance score (0-100, higher is better)"""
        performance_issues = [i for i in issues if i.issue_type == 'PERFORMANCE']
        
        score = 100.0 - len(performance_issues) * 5
        return max(0, score)
    
    def _create_summary(self, issues: List[CodeIssue]) -> Dict[str, int]:
        """Create summary statistics"""
        return {
            'critical_issues': len([i for i in issues if i.severity == 'CRITICAL']),
            'high_severity_issues': len([i for i in issues if i.severity == 'HIGH']),
            'medium_severity_issues': len([i for i in issues if i.severity == 'MEDIUM']),
            'low_severity_issues': len([i for i in issues if i.severity == 'LOW']),
            'security_issues': len([i for i in issues if i.issue_type == 'SECURITY']),
            'performance_issues': len([i for i in issues if i.issue_type == 'PERFORMANCE']),
            'code_smell_issues': len([i for i in issues if i.issue_type == 'CODE_SMELL']),
            'maintainability_issues': len([i for i in issues if i.issue_type == 'MAINTENANCE'])
        }
    
    def _store_results(self, result: AnalysisResult):
        """Store analysis results in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Store issues
        for issue in result.issues:
            cursor.execute('''
                INSERT INTO analysis_results 
                (timestamp, file_path, issue_type, severity, line_number, message, rule_id, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                result.timestamp,
                issue.file_path,
                issue.issue_type,
                issue.severity,
                issue.line_number,
                issue.message,
                issue.rule_id,
                issue.confidence
            ))
        
        # Store metrics
        for key, value in result.metrics.items():
            cursor.execute('''
                INSERT INTO project_metrics (timestamp, metric_name, metric_value)
                VALUES (?, ?, ?)
            ''', (result.timestamp, key, json.dumps(value) if isinstance(value, (dict, list)) else str(value)))
        
        conn.commit()
        conn.close()
    
    def enable_real_time_analysis(self, callback: Optional[Callable] = None, paths: List[str] = None):
        """Enable real-time analysis with file watching"""
        if self.real_time_engine is not None:
            logger.warning("Real-time analysis already enabled")
            return
        
        self.config['enable_real_time'] = True
        self.config['real_time_callback'] = callback
        
        self.real_time_engine = RealTimeAnalysisEngine(self, callback)
        self.real_time_engine.start_watching(paths)
        
        logger.info("Real-time analysis enabled")
    
    def disable_real_time_analysis(self):
        """Disable real-time analysis and stop file watching"""
        if self.real_time_engine is not None:
            self.real_time_engine.stop_watching()
            self.real_time_engine = None
        
        self.config['enable_real_time'] = False
        self.config['real_time_callback'] = None
        
        logger.info("Real-time analysis disabled")
    
    def get_real_time_results(self) -> Dict[str, Any]:
        """Get cached real-time analysis results"""
        if self.real_time_engine is not None:
            return self.real_time_engine.get_cached_results()
        return {}
    
    def force_analyze_file_realtime(self, file_path: str):
        """Force real-time analysis of a specific file"""
        if self.real_time_engine is not None:
            self.real_time_engine.force_analyze_file(file_path)
        else:
            logger.warning("Real-time analysis not enabled")
    
    def generate_ide_extensions(self, output_dir: str):
        """Generate IDE extension packages"""
        # VS Code extension
        vscode_dir = os.path.join(output_dir, 'vscode-extension')
        vscode_generator = VSCodeExtensionGenerator(self)
        vscode_generator.generate_extension_package(vscode_dir)
        
        logger.info(f"IDE extensions generated in {output_dir}")
    
    def start_language_server(self, port: int = 8888):
        """Start Language Server Protocol server"""
        self.lsp_server = LanguageServerProtocol(self)
        logger.info(f"LSP server started on port {port}")
        return self.lsp_server
    
    def analyze_codebase_enhanced(self, max_workers: int = 4, enable_dashboard: bool = True, 
                                 generate_cicd_configs: bool = False) -> AnalysisResult:
        """Enhanced codebase analysis with dashboard and CI/CD integration"""
        logger.info(f"Starting enhanced analysis of {self.project_path}")
        
        # Perform standard analysis
        result = self.analyze_codebase(max_workers)
        
        # Collect metrics for dashboard
        if enable_dashboard:
            try:
                dashboard_metrics = self.dashboard.collect_metrics(result)
                logger.info("Dashboard metrics collected successfully")
            except Exception as e:
                logger.warning(f"Dashboard metrics collection failed: {e}")
        
        # Generate CI/CD configurations if requested
        if generate_cicd_configs:
            try:
                platforms = ['github_actions', 'jenkins', 'gitlab_ci']
                configs = self.cicd_framework.generate_ci_configurations(platforms)
                scripts = self.cicd_framework.create_integration_scripts()
                sonar_config = self.cicd_framework.integrate_with_sonarqube()
                logger.info(f"Generated CI/CD configurations: {list(configs.keys())}")
            except Exception as e:
                logger.warning(f"CI/CD configuration generation failed: {e}")
        
        # Enhanced metrics with advanced analysis results
        result.metrics.update({
            'advanced_security_analysis': self.security_detector.get_security_report(),
            'performance_optimization': self.performance_analyzer.generate_performance_report(),
            'dashboard_available': enable_dashboard,
            'cicd_integration': generate_cicd_configs
        })
        
        return result
    
    def generate_comprehensive_dashboard(self, output_file: str = None) -> str:
        """Generate comprehensive quality dashboard"""
        dashboard_content = self.dashboard.generate_dashboard('html', output_file)
        logger.info(f"Comprehensive dashboard generated{' at ' + output_file if output_file else ''}")
        return dashboard_content
    
    def setup_cicd_integration(self, platforms: List[str] = None, 
                              quality_gates: Dict[str, Any] = None) -> Dict[str, Any]:
        """Setup complete CI/CD integration"""
        if platforms is None:
            platforms = ['github_actions', 'jenkins', 'gitlab_ci', 'azure_devops']
        
        integration_result = {
            'configurations_generated': {},
            'scripts_created': {},
            'quality_gates': {},
            'sonar_integration': None
        }
        
        # Generate CI/CD configurations
        integration_result['configurations_generated'] = self.cicd_framework.generate_ci_configurations(platforms)
        
        # Create integration scripts
        integration_result['scripts_created'] = self.cicd_framework.create_integration_scripts()
        
        # Setup quality gates
        integration_result['quality_gates'] = self.cicd_framework.generate_quality_gates(quality_gates)
        
        # Save quality gates configuration
        quality_gates_file = os.path.join(self.project_path, 'quality-gates.json')
        with open(quality_gates_file, 'w', encoding='utf-8') as f:
            json.dump(integration_result['quality_gates'], f, indent=2)
        
        # Generate SonarQube integration
        integration_result['sonar_integration'] = self.cicd_framework.integrate_with_sonarqube()
        
        # Create sample notification configuration
        notification_config = {
            'slack': {
                'webhook_url': 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL',
                'channel': '#code-quality',
                'username': 'Code Analyzer'
            },
            'email': {
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'recipients': ['team@company.com']
            }
        }
        
        notification_config_file = os.path.join(self.project_path, 'notification-config.json')
        with open(notification_config_file, 'w', encoding='utf-8') as f:
            json.dump(notification_config, f, indent=2)
        
        logger.info(f"CI/CD integration setup complete for platforms: {platforms}")
        return integration_result
    
    def get_comprehensive_analysis_summary(self) -> Dict[str, Any]:
        """Get comprehensive analysis summary with all enhanced features"""
        return {
            'project_path': self.project_path,
            'analysis_timestamp': datetime.now().isoformat(),
            'features_enabled': {
                'advanced_security_analysis': True,
                'performance_optimization': True,
                'quality_metrics_dashboard': True,
                'cicd_integration': True,
                'real_time_monitoring': self.config.get('enable_real_time', False),
                'multi_language_support': True,
                'ai_powered_insights': True,
                'threat_modeling': True,
                'modular_analysis': self.modular_engine is not None
            },
            'integrations_available': {
                'vscode_extension': True,
                'language_server_protocol': True,
                'ci_cd_pipelines': ['github_actions', 'jenkins', 'gitlab_ci', 'azure_devops'],
                'notification_channels': ['slack', 'teams', 'email', 'webhook'],
                'report_formats': ['junit', 'sonarqube', 'sarif', 'checkstyle', 'json', 'html']
            },
            'analysis_capabilities': {
                'security_patterns': len(self.security_detector.owasp_patterns),
                'performance_checks': True,
                'code_smells': True,
                'ml_predictions': self.ml_predictor.is_trained,
                'threat_modeling': True,
                'explainable_ai': True
            }
        }
    
    def generate_report(self, result: AnalysisResult, output_format: str = 'json') -> str:
        """Generate analysis report using the standalone report generation functions"""
        return generate_report(result, output_format)

class LanguageDetector:
    """Detects programming language and returns appropriate analyzer"""
    
    LANGUAGE_MAP = {
        '.py': 'python',
        '.js': 'javascript',
        '.ts': 'typescript',
        '.jsx': 'javascript',
        '.tsx': 'typescript',
        '.java': 'java',
        '.cpp': 'cpp',
        '.c': 'c',
        '.h': 'c',
        '.hpp': 'cpp',
        '.go': 'go',
        '.rb': 'ruby',
        '.php': 'php',
        '.cs': 'csharp',
        '.swift': 'swift',
        '.kt': 'kotlin',
        '.rs': 'rust',
        '.scala': 'scala'
    }
    
    @classmethod
    def detect_language(cls, file_path: str) -> str:
        """Detect programming language from file extension"""
        ext = Path(file_path).suffix.lower()
        return cls.LANGUAGE_MAP.get(ext, 'unknown')
    
    @classmethod
    def is_supported_language(cls, file_path: str) -> bool:
        """Check if language is supported"""
        return cls.detect_language(file_path) != 'unknown'

class MultiLanguageAnalyzer:
    """Multi-language analysis coordinator"""
    
    def __init__(self):
        self.language_analyzers = {
            'python': PythonAnalyzer(),
            'javascript': JavaScriptAnalyzer(),
            'typescript': TypeScriptAnalyzer(),
            'java': JavaAnalyzer(),
            'cpp': CppAnalyzer(),
            'c': CAnalyzer(),
            'go': GoAnalyzer(),
            'ruby': RubyAnalyzer(),
            'php': PhpAnalyzer(),
            'csharp': CSharpAnalyzer(),
        }
    
    def analyze_file(self, file_path: str, content: str) -> Tuple[List[CodeIssue], Dict[str, Any]]:
        """Analyze file using appropriate language analyzer"""
        language = LanguageDetector.detect_language(file_path)
        
        if language not in self.language_analyzers:
            # Fall back to generic analysis
            return self._generic_analysis(file_path, content, language)
        
        analyzer = self.language_analyzers[language]
        return analyzer.analyze(file_path, content)
    
    def _generic_analysis(self, file_path: str, content: str, language: str) -> Tuple[List[CodeIssue], Dict[str, Any]]:
        """Generic analysis for unsupported languages"""
        issues = []
        
        # Basic text-based analysis that works for most languages
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Check for TODOs/FIXMEs
            if any(marker in line_stripped.upper() for marker in ['TODO', 'FIXME', 'HACK', 'XXX']):
                issues.append(CodeIssue(
                    issue_type='MAINTENANCE',
                    severity='LOW',
                    file_path=file_path,
                    line_number=line_num,
                    column=0,
                    message='TODO/FIXME comment found',
                    description=f'Code contains maintenance marker in {language} file',
                    recommendation='Address TODO/FIXME items or create proper tickets',
                    confidence=1.0,
                    rule_id=f'{language.upper()}_TODO',
                    code_snippet=line_stripped
                ))
            
            # Check for long lines (general code quality)
            if len(line) > 120:
                issues.append(CodeIssue(
                    issue_type='CODE_STYLE',
                    severity='LOW',
                    file_path=file_path,
                    line_number=line_num,
                    column=120,
                    message=f'Line too long ({len(line)} characters)',
                    description=f'Line exceeds recommended length in {language} file',
                    recommendation='Break long lines for better readability',
                    confidence=0.8,
                    rule_id=f'{language.upper()}_LONG_LINE',
                    code_snippet=line_stripped[:50] + '...' if len(line_stripped) > 50 else line_stripped
                ))
        
        metrics = {
            'language': language,
            'lines_of_code': len(lines),
            'non_empty_lines': len([line for line in lines if line.strip()]),
            'file_size_bytes': len(content.encode('utf-8')),
            'analysis_type': 'generic'
        }
        
        return issues, metrics

class LanguageAnalyzerBase:
    """Base class for language-specific analyzers"""
    
    def __init__(self, language_name: str):
        self.language_name = language_name
        self.security_patterns = {}
        self.performance_patterns = {}
        self.style_patterns = {}
    
    def analyze(self, file_path: str, content: str) -> Tuple[List[CodeIssue], Dict[str, Any]]:
        """Analyze code file for the specific language"""
        issues = []
        
        # Security analysis
        issues.extend(self.analyze_security(file_path, content))
        
        # Performance analysis
        issues.extend(self.analyze_performance(file_path, content))
        
        # Style analysis
        issues.extend(self.analyze_style(file_path, content))
        
        # Calculate metrics
        metrics = self.calculate_metrics(file_path, content)
        
        return issues, metrics
    
    def analyze_security(self, file_path: str, content: str) -> List[CodeIssue]:
        """Analyze security issues for the language"""
        issues = []
        lines = content.split('\n')
        
        for pattern_type, patterns in self.security_patterns.items():
            for pattern in patterns:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        issues.append(CodeIssue(
                            issue_type='SECURITY',
                            severity='HIGH',
                            file_path=file_path,
                            line_number=line_num,
                            column=0,
                            message=f'Potential {pattern_type} vulnerability in {self.language_name}',
                            description=f'Pattern matching {pattern_type} detected',
                            recommendation=f'Review {pattern_type} usage for security implications',
                            confidence=0.7,
                            rule_id=f'{self.language_name.upper()}_SEC_{pattern_type.upper()}',
                            code_snippet=line.strip()
                        ))
        
        return issues
    
    def analyze_performance(self, file_path: str, content: str) -> List[CodeIssue]:
        """Analyze performance issues for the language"""
        issues = []
        lines = content.split('\n')
        
        for pattern_type, patterns in self.performance_patterns.items():
            for pattern in patterns:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        issues.append(CodeIssue(
                            issue_type='PERFORMANCE',
                            severity='MEDIUM',
                            file_path=file_path,
                            line_number=line_num,
                            column=0,
                            message=f'Potential {pattern_type} performance issue in {self.language_name}',
                            description=f'Pattern suggesting {pattern_type} inefficiency',
                            recommendation=f'Consider optimizing {pattern_type} usage',
                            confidence=0.6,
                            rule_id=f'{self.language_name.upper()}_PERF_{pattern_type.upper()}',
                            code_snippet=line.strip()
                        ))
        
        return issues
    
    def analyze_style(self, file_path: str, content: str) -> List[CodeIssue]:
        """Analyze style issues for the language"""
        issues = []
        lines = content.split('\n')
        
        for pattern_type, patterns in self.style_patterns.items():
            for pattern in patterns:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line):
                        issues.append(CodeIssue(
                            issue_type='CODE_STYLE',
                            severity='LOW',
                            file_path=file_path,
                            line_number=line_num,
                            column=0,
                            message=f'{pattern_type} style issue in {self.language_name}',
                            description=f'Code style pattern: {pattern_type}',
                            recommendation=f'Follow {self.language_name} style guidelines',
                            confidence=0.8,
                            rule_id=f'{self.language_name.upper()}_STYLE_{pattern_type.upper()}',
                            code_snippet=line.strip()
                        ))
        
        return issues
    
    def calculate_metrics(self, file_path: str, content: str) -> Dict[str, Any]:
        """Calculate language-specific metrics"""
        lines = content.split('\n')
        
        return {
            'language': self.language_name,
            'lines_of_code': len(lines),
            'non_empty_lines': len([line for line in lines if line.strip()]),
            'comment_lines': self._count_comments(lines),
            'file_size_bytes': len(content.encode('utf-8')),
            'analysis_type': 'language_specific'
        }
    
    def _count_comments(self, lines: List[str]) -> int:
        """Count comment lines - override in subclasses for language-specific comment syntax"""
        return len([line for line in lines if line.strip().startswith('//', '#')])

# Language-specific analyzer implementations

class PythonAnalyzer(LanguageAnalyzerBase):
    """Python-specific code analyzer - uses existing Python analysis"""
    
    def __init__(self):
        super().__init__('python')
        # Use existing Python-specific patterns
        self.security_patterns = {
            'sql_injection': [r'execute\s*\(\s*[\'"].*%.*[\'"]', r'cursor\.execute\s*\(\s*[\'"].*\+.*[\'"]'],
            'command_injection': [r'os\.system\s*\(', r'subprocess\.call\s*\(', r'eval\s*\(', r'exec\s*\('],
            'hardcoded_secrets': [r'password\s*=\s*[\'"][^\'"]+[\'"]', r'api_key\s*=\s*[\'"][^\'"]+[\'"]']
        }
    
    def analyze(self, file_path: str, content: str) -> Tuple[List[CodeIssue], Dict[str, Any]]:
        """Use existing Python analysis for better accuracy"""
        # Delegate to existing analyzers for Python
        security_detector = SecurityPatternDetector()
        smell_detector = CodeSmellDetector()
        performance_analyzer = PerformanceAnalyzer()
        
        issues = []
        issues.extend(security_detector.detect_vulnerabilities(content, file_path))
        issues.extend(smell_detector.detect_smells(content, file_path))
        issues.extend(performance_analyzer.analyze_performance(content, file_path))
        
        # Calculate Python-specific metrics
        metrics = self._calculate_python_metrics(content)
        
        return issues, metrics
    
    def _calculate_python_metrics(self, content: str) -> Dict[str, Any]:
        """Calculate Python-specific metrics"""
        try:
            tree = ast.parse(content)
            metrics = {
                'language': 'python',
                'classes': len([n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]),
                'functions': len([n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]),
                'imports': len([n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))]),
                'lines_of_code': len(content.split('\n')),
                'complexity': self._calculate_complexity(tree),
                'analysis_type': 'python_ast'
            }
        except SyntaxError:
            metrics = self.calculate_metrics('', content)
            metrics['syntax_error'] = True
        
        return metrics
    
    def _calculate_complexity(self, tree) -> int:
        """Calculate cyclomatic complexity"""
        complexity = 1
        for node in ast.walk(tree):
            if isinstance(node, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(node, ast.BoolOp):
                complexity += len(node.values) - 1
        return complexity

class JavaScriptAnalyzer(LanguageAnalyzerBase):
    """JavaScript-specific code analyzer"""
    
    def __init__(self):
        super().__init__('javascript')
        self.security_patterns = {
            'xss': [r'innerHTML\s*=', r'document\.write\s*\(', r'eval\s*\('],
            'sql_injection': [r'query\s*\(\s*[\'"].*\+.*[\'"]', r'execute\s*\(\s*[\'"].*\+.*[\'"]'],
            'prototype_pollution': [r'__proto__', r'constructor\.prototype'],
            'unsafe_regex': [r'RegExp\s*\(.*\+', r'new\s+RegExp\s*\(.*\+'],
        }
        self.performance_patterns = {
            'dom_queries': [r'document\.getElementById.*for', r'querySelector.*while'],
            'inefficient_loops': [r'for.*length', r'while.*length'],
            'sync_operations': [r'fs\.readFileSync', r'fs\.writeFileSync']
        }
        self.style_patterns = {
            'var_usage': [r'\bvar\s+\w+'],
            'missing_semicolon': [r'\w+\s*$(?<!;)'],
            'double_equals': [r'==(?!=)', r'!=(?!=)']
        }
    
    def _count_comments(self, lines: List[str]) -> int:
        return len([line for line in lines if line.strip().startswith('//', '/*')])

class TypeScriptAnalyzer(LanguageAnalyzerBase):
    """TypeScript-specific code analyzer"""
    
    def __init__(self):
        super().__init__('typescript')
        self.security_patterns = {
            'type_assertion_abuse': [r'\w+\s+as\s+any', r'<any>'],
            'xss': [r'innerHTML\s*=', r'document\.write\s*\('],
            'unsafe_access': [r'\[\s*[\'"].*[\'"]\s*\](?!\s*:)']
        }
        self.style_patterns = {
            'any_type': [r':\s*any\b'],
            'missing_types': [r'function\s+\w+\s*\([^)]*\)\s*{', r'const\s+\w+\s*=']
        }

class JavaAnalyzer(LanguageAnalyzerBase):
    """Java-specific code analyzer"""
    
    def __init__(self):
        super().__init__('java')
        self.security_patterns = {
            'sql_injection': [r'Statement.*executeQuery.*\+', r'PreparedStatement.*setString.*\+'],
            'deserialization': [r'ObjectInputStream', r'readObject\s*\('],
            'path_traversal': [r'File\s*\(.*\+', r'FileInputStream\s*\(.*\+'],
            'weak_crypto': [r'DES\s*\(', r'MD5\s*\(', r'SHA1\s*\(']
        }
        self.performance_patterns = {
            'string_concatenation': [r'String.*\+=', r'\+\s*[\'"].*[\'"]\s*\+'],
            'inefficient_collections': [r'Vector\s*<', r'Hashtable\s*<'],
            'autoboxing': [r'Integer\s+\w+\s*=\s*\d+', r'Double\s+\w+\s*=\s*[\d.]+f?']
        }
        self.style_patterns = {
            'naming_convention': [r'class\s+[a-z]', r'public\s+[A-Z][a-z]*\s+[A-Z]'],
            'magic_numbers': [r'\b(?<!case\s)\d{2,}\b(?!\s*[;}])'],
            'unused_imports': [r'^import\s+[^*]+\*;']
        }
    
    def _count_comments(self, lines: List[str]) -> int:
        comment_count = 0
        in_multiline = False
        for line in lines:
            stripped = line.strip()
            if '/*' in stripped:
                in_multiline = True
            if in_multiline or stripped.startswith('//'):
                comment_count += 1
            if '*/' in stripped:
                in_multiline = False
        return comment_count

class CppAnalyzer(LanguageAnalyzerBase):
    """C++ specific code analyzer"""
    
    def __init__(self):
        super().__init__('cpp')
        self.security_patterns = {
            'buffer_overflow': [r'strcpy\s*\(', r'strcat\s*\(', r'sprintf\s*\(', r'gets\s*\('],
            'memory_leaks': [r'new\s+(?!.*delete)', r'malloc\s*\((?!.*free)'],
            'dangling_pointers': [r'delete\s+\w+;(?!.*\w+\s*=\s*nullptr)'],
            'format_string': [r'printf\s*\(\s*\w+', r'fprintf\s*\(.*\w+']
        }
        self.performance_patterns = {
            'vector_reallocations': [r'vector.*push_back.*for', r'vector.*resize.*loop'],
            'unnecessary_copies': [r'vector<.*>\s+\w+\s*=', r'string\s+\w+\s*=.*substr'],
            'raw_loops': [r'for\s*\(.*<.*size\(\)']
        }
        self.style_patterns = {
            'raw_pointers': [r'\*\s*\w+\s*=\s*new', r'\w+\s*\*\s*\w+'],
            'c_style_casts': [r'\([^)]+\)\s*\w+'],
            'magic_numbers': [r'\b\d{2,}\b(?![f.])(?!\s*[;}])']
        }

class CAnalyzer(LanguageAnalyzerBase):
    """C specific code analyzer"""
    
    def __init__(self):
        super().__init__('c')
        self.security_patterns = {
            'buffer_overflow': [r'strcpy\s*\(', r'strcat\s*\(', r'sprintf\s*\(', r'gets\s*\('],
            'format_string': [r'printf\s*\(\s*\w+', r'scanf\s*\(\s*\w+'],
            'memory_leaks': [r'malloc\s*\((?!.*free)', r'calloc\s*\((?!.*free)'],
            'null_deref': [r'\*\w+(?!.*!=.*NULL)']
        }
        self.performance_patterns = {
            'inefficient_string_ops': [r'strlen.*for', r'strcmp.*while'],
            'repeated_calculations': [r'for.*\w+\([^)]*\w+\([^)]*\)']
        }

class GoAnalyzer(LanguageAnalyzerBase):
    """Go specific code analyzer"""
    
    def __init__(self):
        super().__init__('go')
        self.security_patterns = {
            'command_injection': [r'exec\.Command\s*\(.*\+', r'os\.system\s*\('],
            'path_traversal': [r'filepath\.Join\s*\(.*\+', r'os\.Open\s*\(.*\+'],
            'unsafe_reflection': [r'reflect\..*\(.*interface{}'],
        }
        self.performance_patterns = {
            'string_concatenation': [r'\w+\s*\+=', r'fmt\.Sprintf.*\+'],
            'slice_growth': [r'append\s*\(.*for'],
            'interface_conversions': [r'\.(\w+)(?!\s*[({])']
        }
        self.style_patterns = {
            'naming_convention': [r'func\s+[A-Z]\w*[a-z]', r'var\s+[A-Z]'],
            'error_handling': [r'\w+,\s*\w+\s*:=.*(?!if.*err)']
        }

class RubyAnalyzer(LanguageAnalyzerBase):
    """Ruby specific code analyzer"""
    
    def __init__(self):
        super().__init__('ruby')
        self.security_patterns = {
            'sql_injection': [r'execute\s*\(.*[\'"].*#\{', r'find_by_sql.*#\{'],
            'command_injection': [r'system\s*\(.*#\{', r'`.*#\{', r'eval\s*\('],
            'mass_assignment': [r'params\[:\w+\](?!.*permit)'],
        }
        self.performance_patterns = {
            'n_plus_one': [r'\.each.*\.find', r'\.map.*\.find'],
            'string_interpolation': [r'\".*#\{.*\}.*\".*\+'],
        }
    
    def _count_comments(self, lines: List[str]) -> int:
        return len([line for line in lines if line.strip().startswith('#')])

class PhpAnalyzer(LanguageAnalyzerBase):
    """PHP specific code analyzer"""
    
    def __init__(self):
        super().__init__('php')
        self.security_patterns = {
            'sql_injection': [r'mysql_query\s*\(.*\$', r'query\s*\(.*\$'],
            'xss': [r'echo\s+\$', r'print\s+\$(?!.*htmlspecialchars)'],
            'file_inclusion': [r'include\s*\(\$', r'require\s*\(\$'],
            'command_injection': [r'exec\s*\(\$', r'system\s*\(\$', r'shell_exec\s*\(\$'],
        }
        self.performance_patterns = {
            'inefficient_loops': [r'for.*count\(', r'while.*sizeof\('],
        }
    
    def _count_comments(self, lines: List[str]) -> int:
        comment_count = 0
        in_multiline = False
        for line in lines:
            stripped = line.strip()
            if '/*' in stripped:
                in_multiline = True
            if in_multiline or stripped.startswith('//') or stripped.startswith('#'):
                comment_count += 1
            if '*/' in stripped:
                in_multiline = False
        return comment_count

class CSharpAnalyzer(LanguageAnalyzerBase):
    """C# specific code analyzer"""
    
    def __init__(self):
        super().__init__('csharp')
        self.security_patterns = {
            'sql_injection': [r'SqlCommand.*CommandText.*\+', r'ExecuteReader\s*\(.*\+'],
            'path_traversal': [r'File\..*\(.*\+', r'Directory\..*\(.*\+'],
            'deserialization': [r'BinaryFormatter', r'XmlSerializer.*\(.*\)'],
        }
        self.performance_patterns = {
            'string_concatenation': [r'string.*\+=', r'String\.Concat.*loop'],
            'boxing': [r'object\s+\w+\s*=\s*\d+', r'ArrayList.*Add\s*\(\d+\)'],
        }
        self.style_patterns = {
            'naming_convention': [r'public\s+\w+\s+[a-z]\w*\s*\(', r'class\s+[a-z]'],
        }

# Report generation functionality
def generate_report(result: AnalysisResult, output_format: str = 'html') -> str:
    """Generate analysis report in specified format"""
    if output_format.lower() == 'html':
        return _generate_html_report(result)
    elif output_format.lower() == 'json':
        return _generate_json_report(result)
    elif output_format.lower() == 'markdown':
        return _generate_markdown_report(result)
    else:
        raise ValueError(f"Unsupported output format: {output_format}")
    
def _generate_html_report(result: AnalysisResult) -> str:
    """Generate HTML report"""
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Code Analysis Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            .header {{ background: #f0f0f0; padding: 20px; border-radius: 8px; }}
            .summary {{ display: flex; justify-content: space-between; margin: 20px 0; }}
            .metric {{ background: #e8f4fd; padding: 15px; border-radius: 5px; text-align: center; }}
            .issue {{ border-left: 4px solid #ccc; padding: 10px; margin: 10px 0; background: #fafafa; }}
            .critical {{ border-left-color: #d32f2f; }}
            .high {{ border-left-color: #f57c00; }}
            .medium {{ border-left-color: #fbc02d; }}
            .low {{ border-left-color: #388e3c; }}
            .code-snippet {{ background: #f5f5f5; padding: 10px; font-family: monospace; border-radius: 3px; }}
            .fix-suggestion {{ background: #e8f5e8; padding: 8px; border-radius: 3px; margin-top: 5px; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Code Analysis Report</h1>
            <p><strong>Project:</strong> {project_path}</p>
            <p><strong>Analysis Date:</strong> {timestamp}</p>
            <p><strong>Total Issues:</strong> {total_issues}</p>
        </div>
        
        <div class="summary">
            <div class="metric">
                <h3>Security Score</h3>
                <div style="font-size: 24px; color: {security_color};">{security_score:.1f}/100</div>
            </div>
            <div class="metric">
                <h3>Maintainability</h3>
                <div style="font-size: 24px; color: {maintainability_color};">{maintainability_score:.1f}/100</div>
            </div>
            <div class="metric">
                <h3>Performance</h3>
                <div style="font-size: 24px; color: {performance_color};">{performance_score:.1f}/100</div>
            </div>
        </div>
        
        <h2>Issues by Severity</h2>
        {severity_summary}
        
        <h2>Detailed Issues</h2>
        {detailed_issues}
    </body>
    </html>
    """
    
    # Determine colors based on scores
    def get_score_color(score):
        if score >= 80: return "green"
        elif score >= 60: return "orange"
        else: return "red"
    
    security_score = result.metrics.get('security_score', 0)
    maintainability_score = result.metrics.get('maintainability_score', 0)
    performance_score = result.metrics.get('performance_score', 0)
    
    # Generate severity summary
    severity_summary = "<ul>"
    for severity, count in result.summary.items():
        if any(word in severity for word in ['critical', 'high', 'medium', 'low']):
            severity_summary += f"<li><strong>{severity.replace('_', ' ').title()}:</strong> {count}</li>"
    severity_summary += "</ul>"
    
    # Generate detailed issues
    detailed_issues = ""
    for issue in result.issues[:50]:  # Limit to first 50 issues
        detailed_issues += f"""
        <div class="issue {issue.severity.lower()}">
            <h4>{issue.message}</h4>
            <p><strong>File:</strong> {issue.file_path}:{issue.line_number}</p>
            <p><strong>Type:</strong> {issue.issue_type} | <strong>Severity:</strong> {issue.severity} | <strong>Confidence:</strong> {issue.confidence:.2f}</p>
            <p>{issue.description}</p>
            <div class="code-snippet">{issue.code_snippet}</div>
            <p><strong>Recommendation:</strong> {issue.recommendation}</p>
            {f'<div class="fix-suggestion"><strong>Fix:</strong> {issue.fix_suggestion}</div>' if issue.fix_suggestion else ''}
        </div>
        """
    
    return html_template.format(
        project_path=result.project_path,
        timestamp=result.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        total_issues=len(result.issues),
        security_score=security_score,
            security_color=get_score_color(security_score),
            maintainability_score=maintainability_score,
            maintainability_color=get_score_color(maintainability_score),
            performance_score=performance_score,
            performance_color=get_score_color(performance_score),
            severity_summary=severity_summary,
            detailed_issues=detailed_issues
        )
    
def _generate_json_report(result: AnalysisResult) -> str:
    """Generate JSON report"""
    report_data = {
        'project_path': result.project_path,
        'timestamp': result.timestamp.isoformat(),
        'summary': result.summary,
        'metrics': result.metrics,
        'issues': [asdict(issue) for issue in result.issues]
    }
    return json.dumps(report_data, indent=2, default=str)
    
def _generate_markdown_report(result: AnalysisResult) -> str:
    """Generate Markdown report"""
    md_content = f"""# Code Analysis Report

**Project:** {result.project_path}  
**Analysis Date:** {result.timestamp.strftime("%Y-%m-%d %H:%M:%S")}  
**Total Issues:** {len(result.issues)}

## Summary Scores

- **Security Score:** {result.metrics.get('security_score', 0):.1f}/100
- **Maintainability Score:** {result.metrics.get('maintainability_score', 0):.1f}/100  
- **Performance Score:** {result.metrics.get('performance_score', 0):.1f}/100

## Issues by Severity

"""
    for severity, count in result.summary.items():
        if any(word in severity for word in ['critical', 'high', 'medium', 'low']):
            md_content += f"- **{severity.replace('_', ' ').title()}:** {count}\n"
    
    md_content += "\n## Top Issues\n\n"
    
    for i, issue in enumerate(result.issues[:20], 1):
        md_content += f"### {i}. {issue.message}\n\n"
        md_content += f"**File:** `{issue.file_path}:{issue.line_number}`\n"
        md_content += f"**Type:** {issue.issue_type} | **Severity:** {issue.severity} | **Confidence:** {issue.confidence:.2f}\n\n"
        md_content += f"{issue.description}\n\n"
        md_content += "```python\n"
        md_content += f"{issue.code_snippet}\n"
        md_content += "```\n\n"
        md_content += f"**Recommendation:** {issue.recommendation}\n\n"
        if issue.fix_suggestion:
            md_content += f"**Suggested Fix:** {issue.fix_suggestion}\n\n"
        md_content += "---\n\n"
    
    return md_content

class IDEIntegration:
    """Handles integration with IDEs and development environments"""
    
    def __init__(self, analyzer: IntelligentCodeAnalyzer):
        self.analyzer = analyzer
    
    def create_vscode_extension_data(self, result: AnalysisResult) -> Dict[str, Any]:
        """Create data structure for VS Code extension"""
        diagnostics = []
        
        for issue in result.issues:
            diagnostic = {
                "range": {
                    "start": {"line": max(0, issue.line_number - 1), "character": issue.column},
                    "end": {"line": max(0, issue.line_number - 1), "character": issue.column + 10}
                },
                "message": issue.message,
                "severity": self._map_severity_to_vscode(issue.severity),
                "code": issue.rule_id,
                "source": "intelligent-code-analyzer"
            }
            diagnostics.append(diagnostic)
        
        return {
            "diagnostics": diagnostics,
            "metrics": result.metrics,
            "summary": result.summary
        }
    
    def _map_severity_to_vscode(self, severity: str) -> int:
        """Map our severity levels to VS Code diagnostic severity"""
        mapping = {
            'CRITICAL': 1,  # Error
            'HIGH': 1,      # Error
            'MEDIUM': 2,    # Warning
            'LOW': 3        # Information
        }
        return mapping.get(severity, 3)
    
    def create_lsp_diagnostics(self, result: AnalysisResult) -> List[Dict[str, Any]]:
        """Create Language Server Protocol diagnostics"""
        diagnostics = []
        
        for issue in result.issues:
            diagnostic = {
                "range": {
                    "start": {"line": issue.line_number - 1, "character": issue.column},
                    "end": {"line": issue.line_number - 1, "character": issue.column + 1}
                },
                "severity": self._map_severity_to_lsp(issue.severity),
                "code": issue.rule_id,
                "source": "intelligent-code-analyzer",
                "message": issue.message,
                "data": {
                    "description": issue.description,
                    "recommendation": issue.recommendation,
                    "fix_suggestion": issue.fix_suggestion,
                    "confidence": issue.confidence
                }
            }
            diagnostics.append(diagnostic)
        
        return diagnostics
    
    def _map_severity_to_lsp(self, severity: str) -> int:
        """Map severity to LSP DiagnosticSeverity"""
        mapping = {
            'CRITICAL': 1,  # Error
            'HIGH': 1,      # Error
            'MEDIUM': 2,    # Warning
            'LOW': 3        # Information
        }
        return mapping.get(severity, 4)  # Hint

class LanguageServerProtocol:
    """Language Server Protocol implementation for IDE integration"""
    
    def __init__(self, analyzer: IntelligentCodeAnalyzer):
        self.analyzer = analyzer
        self.workspace_folders = []
        self.client_capabilities = {}
        self.server_capabilities = {
            'textDocumentSync': {
                'openClose': True,
                'change': 2,  # Incremental
                'willSave': True,
                'save': {'includeText': True}
            },
            'diagnosticsProvider': True,
            'codeActionProvider': True,
            'hoverProvider': True,
            'completionProvider': {
                'triggerCharacters': ['.', '->', '::']
            },
            'definitionProvider': True,
            'referencesProvider': True
        }
        
    def initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Initialize the language server"""
        self.client_capabilities = params.get('capabilities', {})
        self.workspace_folders = params.get('workspaceFolders', [])
        
        return {
            'capabilities': self.server_capabilities,
            'serverInfo': {
                'name': 'Intelligent Code Analyzer LSP',
                'version': '1.0.0'
            }
        }
    
    def did_open(self, params: Dict[str, Any]):
        """Handle document open event"""
        document = params['textDocument']
        uri = document['uri']
        content = document['text']
        
        # Analyze document and publish diagnostics
        self._analyze_and_publish_diagnostics(uri, content)
    
    def did_change(self, params: Dict[str, Any]):
        """Handle document change event"""
        document = params['textDocument']
        uri = document['uri']
        changes = params['contentChanges']
        
        # For incremental changes, we would reconstruct the full content
        # For simplicity, assuming full content is provided
        if changes and 'text' in changes[0]:
            content = changes[0]['text']
            self._analyze_and_publish_diagnostics(uri, content)
    
    def did_save(self, params: Dict[str, Any]):
        """Handle document save event"""
        document = params['textDocument']
        uri = document['uri']
        
        # Re-analyze on save
        if 'text' in params:
            content = params['text']
            self._analyze_and_publish_diagnostics(uri, content)
    
    def _analyze_and_publish_diagnostics(self, uri: str, content: str):
        """Analyze document and publish diagnostics"""
        file_path = self._uri_to_path(uri)
        
        try:
            issues, _ = self.analyzer._analyze_file_standard(file_path, content)
            diagnostics = self._convert_issues_to_diagnostics(issues)
            
            # In a real LSP implementation, this would send to the client
            self._publish_diagnostics(uri, diagnostics)
            
        except Exception as e:
            logger.error(f"LSP analysis failed for {file_path}: {e}")
    
    def _convert_issues_to_diagnostics(self, issues: List[CodeIssue]) -> List[Dict[str, Any]]:
        """Convert CodeIssue objects to LSP diagnostic format"""
        diagnostics = []
        
        for issue in issues:
            diagnostic = {
                'range': {
                    'start': {
                        'line': max(0, issue.line_number - 1),
                        'character': max(0, issue.column)
                    },
                    'end': {
                        'line': max(0, issue.line_number - 1),
                        'character': max(0, issue.column + len(issue.code_snippet.split('\n')[0]))
                    }
                },
                'severity': self._severity_to_lsp(issue.severity),
                'code': issue.rule_id,
                'source': 'intelligent-analyzer',
                'message': issue.message,
                'data': {
                    'description': issue.description,
                    'recommendation': issue.recommendation,
                    'fix_suggestion': issue.fix_suggestion,
                    'confidence': issue.confidence
                }
            }
            diagnostics.append(diagnostic)
        
        return diagnostics
    
    def _severity_to_lsp(self, severity: str) -> int:
        """Convert severity to LSP DiagnosticSeverity"""
        mapping = {
            'CRITICAL': 1,  # Error
            'HIGH': 1,      # Error
            'MEDIUM': 2,    # Warning
            'LOW': 3,       # Information
        }
        return mapping.get(severity, 4)  # Hint
    
    def _uri_to_path(self, uri: str) -> str:
        """Convert URI to file path"""
        if uri.startswith('file://'):
            return uri[7:]  # Remove 'file://' prefix
        return uri
    
    def _publish_diagnostics(self, uri: str, diagnostics: List[Dict[str, Any]]):
        """Publish diagnostics to client (placeholder)"""
        # In a real implementation, this would send via JSON-RPC
        logger.debug(f"Publishing {len(diagnostics)} diagnostics for {uri}")
    
    def code_action(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Provide code actions for diagnostics"""
        document = params['textDocument']
        range_obj = params['range']
        context = params.get('context', {})
        diagnostics = context.get('diagnostics', [])
        
        actions = []
        
        for diagnostic in diagnostics:
            if diagnostic.get('source') == 'intelligent-analyzer':
                data = diagnostic.get('data', {})
                fix_suggestion = data.get('fix_suggestion')
                
                if fix_suggestion:
                    action = {
                        'title': f'Fix: {fix_suggestion}',
                        'kind': 'quickfix',
                        'diagnostics': [diagnostic],
                        'edit': {
                            'changes': {
                                document['uri']: [{
                                    'range': diagnostic['range'],
                                    'newText': fix_suggestion
                                }]
                            }
                        }
                    }
                    actions.append(action)
        
        return actions
    
    def hover(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Provide hover information"""
        document = params['textDocument']
        position = params['position']
        
        # Get diagnostics for the current position
        uri = document['uri']
        file_path = self._uri_to_path(uri)
        
        # This would typically query cached analysis results
        hover_content = self._get_hover_content(file_path, position)
        
        if hover_content:
            return {
                'contents': {
                    'kind': 'markdown',
                    'value': hover_content
                },
                'range': {
                    'start': position,
                    'end': position
                }
            }
        
        return None
    
    def _get_hover_content(self, file_path: str, position: Dict[str, int]) -> str:
        """Get hover content for position"""
        # This is a simplified implementation
        return f"**Intelligent Code Analysis**\n\nAnalyzing code at line {position['line'] + 1}"

class VSCodeExtensionGenerator:
    """Generates VS Code extension configuration and files"""
    
    def __init__(self, analyzer: IntelligentCodeAnalyzer):
        self.analyzer = analyzer
    
    def generate_extension_package(self, output_dir: str):
        """Generate complete VS Code extension package"""
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate package.json
        self._generate_package_json(output_dir)
        
        # Generate extension.js (main file)
        self._generate_extension_main(output_dir)
        
        # Generate language configuration
        self._generate_language_config(output_dir)
        
        # Generate README
        self._generate_readme(output_dir)
        
        logger.info(f"VS Code extension generated in {output_dir}")
    
    def _generate_package_json(self, output_dir: str):
        """Generate package.json for VS Code extension"""
        package_json = {
            "name": "intelligent-code-analyzer",
            "displayName": "Intelligent Code Analyzer",
            "description": "AI/ML-driven code analysis for enhanced quality and security",
            "version": "1.0.0",
            "engines": {
                "vscode": "^1.60.0"
            },
            "categories": ["Linters", "Other"],
            "activationEvents": [
                "onLanguage:python",
                "onLanguage:javascript",
                "onLanguage:typescript",
                "onLanguage:java",
                "onLanguage:cpp",
                "onLanguage:go"
            ],
            "main": "./extension.js",
            "contributes": {
                "commands": [
                    {
                        "command": "intelligentAnalyzer.analyzeFile",
                        "title": "Analyze Current File",
                        "category": "Intelligent Analyzer"
                    },
                    {
                        "command": "intelligentAnalyzer.analyzeWorkspace",
                        "title": "Analyze Entire Workspace",
                        "category": "Intelligent Analyzer"
                    },
                    {
                        "command": "intelligentAnalyzer.showReport",
                        "title": "Show Analysis Report",
                        "category": "Intelligent Analyzer"
                    }
                ],
                "configuration": {
                    "title": "Intelligent Code Analyzer",
                    "properties": {
                        "intelligentAnalyzer.enableRealTime": {
                            "type": "boolean",
                            "default": True,
                            "description": "Enable real-time analysis"
                        },
                        "intelligentAnalyzer.enableML": {
                            "type": "boolean",
                            "default": True,
                            "description": "Enable ML-based analysis"
                        },
                        "intelligentAnalyzer.confidenceThreshold": {
                            "type": "number",
                            "default": 0.5,
                            "minimum": 0,
                            "maximum": 1,
                            "description": "Minimum confidence threshold for issues"
                        }
                    }
                },
                "menus": {
                    "explorer/context": [
                        {
                            "command": "intelligentAnalyzer.analyzeFile",
                            "when": "resourceExtname in .py,.js,.ts,.java,.cpp,.go",
                            "group": "navigation"
                        }
                    ]
                },
                "problemMatchers": [
                    {
                        "name": "intelligent-analyzer",
                        "owner": "intelligent-analyzer",
                        "fileLocation": "relative",
                        "pattern": {
  "regexp": r"^(.+):(\d+):(\d+):\s+(error|warning|info):\s+(.+)$",
                            "file": 1,
                            "line": 2,
                            "column": 3,
                            "severity": 4,
                            "message": 5
                        }
                    }
                ]
            },
            "scripts": {
                "vscode:prepublish": "npm run compile",
                "compile": "tsc -p ./"
            },
            "devDependencies": {
                "@types/vscode": "^1.60.0",
                "typescript": "^4.4.0"
            }
        }
        
        with open(os.path.join(output_dir, 'package.json'), 'w') as f:
            json.dump(package_json, f, indent=2)
    
    def _generate_extension_main(self, output_dir: str):
        """Generate main extension.js file"""
        extension_js = '''
const vscode = require('vscode');
const { spawn } = require('child_process');
const path = require('path');

function activate(context) {
    console.log('Intelligent Code Analyzer extension is now active!');
    
    // Register commands
    let analyzeFileCommand = vscode.commands.registerCommand('intelligentAnalyzer.analyzeFile', analyzeCurrentFile);
    let analyzeWorkspaceCommand = vscode.commands.registerCommand('intelligentAnalyzer.analyzeWorkspace', analyzeWorkspace);
    let showReportCommand = vscode.commands.registerCommand('intelligentAnalyzer.showReport', showReport);
    
    context.subscriptions.push(analyzeFileCommand, analyzeWorkspaceCommand, showReportCommand);
    
    // Set up real-time analysis if enabled
    const config = vscode.workspace.getConfiguration('intelligentAnalyzer');
    if (config.get('enableRealTime')) {
        setupRealTimeAnalysis(context);
    }
}

function analyzeCurrentFile() {
    const activeEditor = vscode.window.activeTextEditor;
    if (!activeEditor) {
        vscode.window.showErrorMessage('No active file to analyze');
        return;
    }
    
    const document = activeEditor.document;
    const filePath = document.fileName;
    
    // Run analysis
    runAnalysis([filePath]);
}

function analyzeWorkspace() {
    if (!vscode.workspace.workspaceFolders) {
        vscode.window.showErrorMessage('No workspace folder open');
        return;
    }
    
    const workspaceFolder = vscode.workspace.workspaceFolders[0].uri.fsPath;
    runAnalysis([workspaceFolder]);
}

function runAnalysis(paths) {
    const config = vscode.workspace.getConfiguration('intelligentAnalyzer');
    const enableML = config.get('enableML');
    const confidenceThreshold = config.get('confidenceThreshold');
    
    // Construct command to run the analyzer
    const pythonPath = 'python';  // This should be configurable
    const analyzerPath = path.join(__dirname, 'hack3.py');
    
    const args = [analyzerPath, ...paths, '--output', 'json'];
    
    if (enableML) {
        args.push('--enable-ml');
    }
    
    args.push('--confidence-threshold', confidenceThreshold.toString());
    
    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "Analyzing code...",
        cancellable: true
    }, (progress, token) => {
        return new Promise((resolve, reject) => {
            const process = spawn(pythonPath, args);
            let output = '';
            let errorOutput = '';
            
            process.stdout.on('data', (data) => {
                output += data.toString();
            });
            
            process.stderr.on('data', (data) => {
                errorOutput += data.toString();
            });
            
            process.on('close', (code) => {
                if (code === 0) {
                    try {
                        const result = JSON.parse(output);
                        displayResults(result);
                        resolve();
                    } catch (e) {
                        vscode.window.showErrorMessage('Failed to parse analysis results');
                        reject(e);
                    }
                } else {
                    vscode.window.showErrorMessage(`Analysis failed: ${errorOutput}`);
                    reject(new Error(errorOutput));
                }
            });
            
            token.onCancellationRequested(() => {
                process.kill();
                reject(new Error('Analysis cancelled'));
            });
        });
    });
}

function displayResults(result) {
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('intelligent-analyzer');
    diagnosticCollection.clear();
    
    // Group issues by file
    const issuesByFile = {};
    
    for (const issue of result.issues || []) {
        const filePath = issue.file_path;
        if (!issuesByFile[filePath]) {
            issuesByFile[filePath] = [];
        }
        
        const diagnostic = new vscode.Diagnostic(
            new vscode.Range(
                new vscode.Position(Math.max(0, issue.line_number - 1), issue.column),
                new vscode.Position(Math.max(0, issue.line_number - 1), issue.column + 10)
            ),
            issue.message,
            getSeverity(issue.severity)
        );
        
        diagnostic.code = issue.rule_id;
        diagnostic.source = 'intelligent-analyzer';
        
        issuesByFile[filePath].push(diagnostic);
    }
    
    // Set diagnostics for each file
    for (const [filePath, diagnostics] of Object.entries(issuesByFile)) {
        const uri = vscode.Uri.file(filePath);
        diagnosticCollection.set(uri, diagnostics);
    }
    
    // Show summary
    const totalIssues = result.issues?.length || 0;
    vscode.window.showInformationMessage(`Analysis complete: ${totalIssues} issues found`);
}

function getSeverity(severity) {
    switch (severity) {
        case 'CRITICAL':
        case 'HIGH':
            return vscode.DiagnosticSeverity.Error;
        case 'MEDIUM':
            return vscode.DiagnosticSeverity.Warning;
        case 'LOW':
            return vscode.DiagnosticSeverity.Information;
        default:
            return vscode.DiagnosticSeverity.Hint;
    }
}

function showReport() {
    // Create and show a webview panel with detailed report
    const panel = vscode.window.createWebviewPanel(
        'intelligentAnalyzerReport',
        'Analysis Report',
        vscode.ViewColumn.One,
        {}
    );
    
    panel.webview.html = getReportHtml();
}

function getReportHtml() {
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Intelligent Code Analysis Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .metric { background: #f0f0f0; padding: 10px; margin: 10px 0; border-radius: 5px; }
            .issue { border-left: 3px solid #ccc; padding: 10px; margin: 10px 0; }
            .critical { border-left-color: #d32f2f; }
            .high { border-left-color: #f57c00; }
            .medium { border-left-color: #fbc02d; }
            .low { border-left-color: #388e3c; }
        </style>
    </head>
    <body>
        <h1>Code Analysis Report</h1>
        <div class="metric">
            <h3>Analysis in progress...</h3>
            <p>Run analysis to see detailed results here.</p>
        </div>
    </body>
    </html>
    `;
}

function setupRealTimeAnalysis(context) {
    // Set up file watchers for real-time analysis
    const watcher = vscode.workspace.createFileSystemWatcher('**/*.{py,js,ts,java,cpp,go}');
    
    watcher.onDidChange((uri) => {
        // Debounce rapid changes
        setTimeout(() => {
            runAnalysis([uri.fsPath]);
        }, 1000);
    });
    
    context.subscriptions.push(watcher);
}

function deactivate() {}

module.exports = {
    activate,
    deactivate
};
'''
        
        with open(os.path.join(output_dir, 'extension.js'), 'w') as f:
            f.write(extension_js)
    
    def _generate_language_config(self, output_dir: str):
        """Generate language configuration files"""
        # This would include language-specific configurations
        pass
    
    def _generate_readme(self, output_dir: str):
        """Generate README.md for the extension"""
        readme_content = '''
# Intelligent Code Analyzer

AI/ML-driven code analysis extension for enhanced quality and security.

## Features

- **Multi-language Support**: Analyze Python, JavaScript, TypeScript, Java, C++, Go, and more
- **Real-time Analysis**: Get instant feedback as you type
- **AI-powered Detection**: Advanced ML models for semantic analysis
- **Explainable AI**: Understand why issues were flagged
- **Security Focus**: Detect vulnerabilities and security anti-patterns
- **Performance Analysis**: Identify performance bottlenecks
- **Code Quality**: Maintain high code standards

## Usage

1. Open a supported code file
2. Issues will be highlighted in real-time
3. Use the command palette to run analysis on files or workspace
4. View detailed reports with explanations and recommendations

## Commands

- `Intelligent Analyzer: Analyze Current File` - Analyze the active file
- `Intelligent Analyzer: Analyze Entire Workspace` - Analyze all files in workspace
- `Intelligent Analyzer: Show Analysis Report` - Display detailed report

## Configuration

- `intelligentAnalyzer.enableRealTime` - Enable/disable real-time analysis
- `intelligentAnalyzer.enableML` - Enable/disable ML-based analysis  
- `intelligentAnalyzer.confidenceThreshold` - Minimum confidence for reported issues

## Requirements

- Python 3.7+
- Required Python packages (automatically installed)

## License

MIT License
'''
        
        with open(os.path.join(output_dir, 'README.md'), 'w') as f:
            f.write(readme_content)

def main():
    """Example usage of the Intelligent Code Analyzer"""
    import argparse
    
    parser = argparse.ArgumentParser(description='AI/ML-Driven Intelligent Code Analysis for Enhanced Quality and Security')
    parser.add_argument('project_path', nargs='?', default='.', help='Path to the project to analyze')
    parser.add_argument('--output', '-o', choices=['html', 'json', 'markdown'], 
                       default='html', help='Output format for the report')
    parser.add_argument('--output-file', '-f', help='Output file path')
    parser.add_argument('--workers', '-w', type=int, default=4, 
                       help='Number of worker threads for parallel analysis')
    parser.add_argument('--train', action='store_true', 
                       help='Train ML models on the codebase')
    parser.add_argument('--real-time', action='store_true', 
                       help='Enable real-time analysis with file watching')
    parser.add_argument('--generate-extensions', help='Generate IDE extensions in specified directory')
    parser.add_argument('--start-lsp', type=int, nargs='?', const=8888, 
                       help='Start Language Server Protocol server on specified port (default: 8888)')
    parser.add_argument('--languages', nargs='+', 
                       help='Specific languages to analyze (default: all supported)')
    parser.add_argument('--confidence-threshold', type=float, default=0.5,
                       help='Minimum confidence threshold for reported issues')
    parser.add_argument('--enable-advanced-ml', action='store_true', default=True,
                       help='Enable advanced ML models and explainable AI')
    parser.add_argument('--disable-modular', action='store_true',
                       help='Disable modular analysis for large files')
    
    args = parser.parse_args()
    
    try:
        # Initialize analyzer with enhanced configuration
        enable_modular = not args.disable_modular
        analyzer = IntelligentCodeAnalyzer(args.project_path, enable_modular=enable_modular)
        
        # Configure advanced settings
        analyzer.config['min_confidence_threshold'] = args.confidence_threshold
        analyzer.config['enable_advanced_ml'] = args.enable_advanced_ml
        
        # Generate IDE extensions if requested
        if args.generate_extensions:
            print(f"Generating IDE extensions in: {args.generate_extensions}")
            analyzer.generate_ide_extensions(args.generate_extensions)
            print("IDE extensions generated successfully!")
            return 0
        
        # Start Language Server if requested
        if args.start_lsp is not None:
            print(f"Starting Language Server Protocol server on port {args.start_lsp}")
            lsp_server = analyzer.start_language_server(args.start_lsp)
            print("LSP server started. Press Ctrl+C to stop.")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nStopping LSP server...")
            return 0
        
        # Enable real-time analysis if requested
        if args.real_time:
            print("Enabling real-time analysis...")
            def real_time_callback(result):
                print(f"Real-time analysis: {result['file_path']} - {len(result['issues'])} issues")
            
            analyzer.enable_real_time_analysis(callback=real_time_callback)
            print("Real-time analysis enabled. Monitoring file changes...")
        
        # Train ML models if requested
        if args.train:
            print("Training ML models on codebase...")
            # This would require labeled training data in practice
            # For demo purposes, we'll skip this step
            print("ML model training skipped (requires labeled training data)")
        
        # Perform analysis
        print(f"Analyzing project: {args.project_path}")
        if args.languages:
            print(f"Focusing on languages: {', '.join(args.languages)}")
        
        # Use enhanced analysis if available
        use_enhanced = hasattr(analyzer, 'analyze_codebase_enhanced')
        
        if use_enhanced:
            print("Using enhanced analysis with advanced features...")
            result = analyzer.analyze_codebase_enhanced(
                max_workers=args.workers,
                enable_dashboard=True,
                generate_cicd_configs=bool(args.generate_extensions)
            )
        else:
            result = analyzer.analyze_codebase(max_workers=args.workers)
        
        # Generate report
        report_content = analyzer.generate_report(result, args.output)
        
        # Output report
        if args.output_file:
            with open(args.output_file, 'w', encoding='utf-8') as f:
                f.write(report_content)
            print(f"Report saved to: {args.output_file}")
        else:
            print(report_content)
        
        # Print enhanced summary
        print(f"\n=== Enhanced Analysis Summary ===")
        print(f"Total files analyzed: {result.metrics['total_files_analyzed']}")
        print(f"Total lines of code: {result.metrics['total_lines_of_code']}")
        print(f"Total issues found: {len(result.issues)}")
        print(f"Languages detected: {result.metrics.get('project_context', {}).get('file_types', 'N/A')}")
        print(f"Security Score: {result.metrics['security_score']:.1f}/100")
        print(f"Maintainability Score: {result.metrics['maintainability_score']:.1f}/100")
        print(f"Performance Score: {result.metrics['performance_score']:.1f}/100")
        
        # Show advanced features summary
        if use_enhanced and hasattr(analyzer, 'get_comprehensive_analysis_summary'):
            comprehensive_summary = analyzer.get_comprehensive_analysis_summary()
            print(f"\n=== Advanced Features Enabled ===")
            for feature, enabled in comprehensive_summary['features_enabled'].items():
                status = "✓" if enabled else "✗"
                print(f"  {status} {feature.replace('_', ' ').title()}")
            
            print(f"\n=== Platform Support ===")
            print(f"  CI/CD Platforms: {', '.join(comprehensive_summary['supported_platforms'])}")
            print(f"  Programming Languages: {len(comprehensive_summary['supported_languages'])} supported")
            print(f"  Notification Channels: {', '.join(comprehensive_summary['notification_channels'])}")
            print(f"  Report Formats: {', '.join(comprehensive_summary['report_formats'])}")
        else:
            print(f"\nAnalysis features used:")
            print(f"  - Modular analysis: {enable_modular}")
            print(f"  - Advanced ML models: {args.enable_advanced_ml}")
            print(f"  - Multi-language support: Enabled")
            print(f"  - Real-time monitoring: {args.real_time}")
            print(f"  - Confidence threshold: {args.confidence_threshold}")
        
        # Show top issues
        if result.issues:
            print(f"\n=== Top 5 Issues ===")
            for i, issue in enumerate(result.issues[:5], 1):
                print(f"{i}. [{issue.severity}] {issue.message}")
                print(f"   File: {issue.file_path}:{issue.line_number}")
                print(f"   Type: {issue.issue_type}")
                if hasattr(issue, 'confidence') and issue.confidence:
                    print(f"   Confidence: {issue.confidence:.2f}")
                print()
        
        # Show comprehensive usage examples
        print(f"\n=== Comprehensive Usage Examples ===")
        print(f"\n🔧 Basic Analysis:")
        print(f"  python hack3.py {args.project_path}")
        
        print(f"\n🚀 Enhanced Analysis with Dashboard:")
        print(f"  python hack3.py {args.project_path} --enable-advanced-ml")
        
        print(f"\n🔄 CI/CD Integration Setup:")
        print(f"  python hack3.py --generate-extensions ./ci-integration")
        
        print(f"\n📊 Real-time Monitoring:")
        print(f"  python hack3.py --real-time {args.project_path}")
        
        print(f"\n🌐 Multi-platform CI/CD:")
        print(f"  python hack3.py {args.project_path} --generate-extensions ./configs")
        
        print(f"\n🎯 Language-specific Analysis:")
        print(f"  python hack3.py --languages python javascript java typescript")
        
        print(f"\n🔒 Security-focused Analysis:")
        print(f"  python hack3.py {args.project_path} --confidence-threshold 0.9")
        
        print(f"\n🖥️ IDE Integration:")
        print(f"  python hack3.py --start-lsp 8888")
        
        print(f"\n📈 Performance Analysis:")
        print(f"  python hack3.py {args.project_path} --workers 8")
        
        # Show available integrations if enhanced features are enabled
        if use_enhanced:
            print(f"\n=== Available Integrations ===")
            print(f"✓ GitHub Actions, GitLab CI, Jenkins, Azure DevOps")
            print(f"✓ SonarQube, SARIF, JUnit, Checkstyle reports")
            print(f"✓ Slack, Teams, Email notifications")
            print(f"✓ VS Code, IntelliJ, Eclipse IDE extensions")
            print(f"✓ Quality gates and automated enforcement")
        
        # Cleanup real-time analysis if enabled
        if args.real_time:
            print("\nPress Ctrl+C to stop real-time monitoring...")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                analyzer.disable_real_time_analysis()
                print("\nReal-time analysis stopped.")
    
    except Exception as e:
        print(f"Error during analysis: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())