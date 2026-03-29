import re
from config import SECURITY_POLICIES, PROTOCOL_REQUIREMENTS

class PolicyEngine:
    def __init__(self, code, symbol_table, ast):
        self.code = code
        self.lines = code.split('\n')
        self.symbol_table = symbol_table
        self.ast = ast
        self.issues = []

    def enforce(self):
        """Enforce all security policies"""
        if SECURITY_POLICIES.get("TLS_REQUIRED", True):
            self.check_tls_required()
        
        if SECURITY_POLICIES.get("DTLS_REQUIRED_FOR_COAP", True):
            self.check_coap_dtls()
        
        if SECURITY_POLICIES.get("NO_HARDCODED_KEYS", True):
            self.check_no_hardcoded_keys()
        
        if SECURITY_POLICIES.get("NO_HARDCODED_CREDENTIALS", True):
            self.check_no_hardcoded_credentials()
        
        if SECURITY_POLICIES.get("STRONG_CRYPTO_ONLY", True):
            self.check_strong_crypto_only()
        
        if SECURITY_POLICIES.get("MUTUAL_AUTH_REQUIRED", False):
            self.check_mutual_auth()
        
        # Add authentication and topic checks
        self.check_missing_authentication()
        self.check_topic_restrictions()
    
        return self.issues

    def check_missing_authentication(self):
        """Check for MQTT/CoAP connections without authentication"""
        for line_num, line in enumerate(self.lines, 1):
            # MQTT connect without username/password/cert
            if 'mqtt_connect' in line:
                has_username = 'username' in line.lower() or 'user' in line.lower()
                has_password = 'password' in line.lower() or 'pass' in line.lower()
                has_cert = 'cert' in line.lower() or 'cafile' in line.lower()
                
                if not (has_username or has_cert):
                    self.issues.append({
                        "type": "POLICY_VIOLATION",
                        "policy": "AUTHENTICATION_REQUIRED",
                        "description": "MQTT connection without authentication",
                        "line": line_num,
                        "code_snippet": line.strip()[:80],
                        "severity": "HIGH",
                        "remediation": "Add username/password or client certificate"
                    })
            
            # CoAP without authentication
            if 'coap_send' in line or 'coap_connect' in line:
                has_psk = 'psk' in line.lower()
                has_cert = 'cert' in line.lower()
                
                if not (has_psk or has_cert):
                    self.issues.append({
                        "type": "POLICY_VIOLATION",
                        "policy": "AUTHENTICATION_REQUIRED",
                        "description": "CoAP connection without authentication",
                        "line": line_num,
                        "code_snippet": line.strip()[:80],
                        "severity": "HIGH",
                        "remediation": "Add PSK or certificate authentication"
                    })

    def check_topic_restrictions(self):
        """Enforce topic/URI access restrictions"""
        restricted_patterns = ['admin/', 'internal/', 'config/', 'secret/', 'private/']
        
        for line_num, line in enumerate(self.lines, 1):
            if 'mqtt_publish' in line or 'mqtt_subscribe' in line or 'coap_send' in line:
                for pattern in restricted_patterns:
                    if pattern in line:
                        self.issues.append({
                            "type": "POLICY_VIOLATION",
                            "policy": "TOPIC_RESTRICTION",
                            "description": f"Restricted topic pattern '{pattern}' used",
                            "line": line_num,
                            "code_snippet": line.strip()[:80],
                            "severity": "MEDIUM",
                            "remediation": f"Use allowed topic pattern instead of '{pattern}'"
                        })

    def check_tls_required(self):
        """Ensure all network communication uses TLS"""
        for line_num, line in enumerate(self.lines, 1):
            # Check for MQTT without TLS
            if 'mqtt://' in line and 'mqtts://' not in line:
                self.issues.append({
                    "type": "POLICY_VIOLATION",
                    "policy": "TLS_REQUIRED",
                    "description": "MQTT connection without TLS encryption",
                    "line": line_num,
                    "code_snippet": line.strip()[:80],
                    "severity": "CRITICAL",
                    "remediation": "Replace mqtt:// with mqtts:// and configure TLS certificates"
                })
            
            # Check for HTTP without HTTPS
            if 'http://' in line and 'https://' not in line and 'localhost' not in line and '127.0.0.1' not in line:
                self.issues.append({
                    "type": "POLICY_VIOLATION",
                    "policy": "TLS_REQUIRED",
                    "description": "HTTP connection without TLS (HTTPS)",
                    "line": line_num,
                    "code_snippet": line.strip()[:80],
                    "severity": "HIGH",
                    "remediation": "Use HTTPS instead of HTTP"
                })

    def check_coap_dtls(self):
        """Ensure CoAP uses DTLS"""
        for line_num, line in enumerate(self.lines, 1):
            if 'coap://' in line and 'coaps://' not in line:
                self.issues.append({
                    "type": "POLICY_VIOLATION",
                    "policy": "DTLS_REQUIRED_FOR_COAP",
                    "description": "CoAP without DTLS - no security",
                    "line": line_num,
                    "code_snippet": line.strip()[:80],
                    "severity": "CRITICAL",
                    "remediation": "Use coaps:// (CoAP over DTLS)"
                })

    def check_no_hardcoded_keys(self):
        """Flag hardcoded cryptographic keys"""
        key_patterns = [
            (r'(aes|AES)_key\s*=\s*"[A-Fa-f0-9]{32,}"', "Hardcoded AES key"),
            (r'private_key\s*=\s*"-----BEGIN', "Hardcoded private key"),
            (r'api_key\s*=\s*"[A-Za-z0-9]{20,}"', "Hardcoded API key"),
            (r'signing_key\s*=\s*"[^"]{20,}"', "Hardcoded signing key"),
        ]
        
        for line_num, line in enumerate(self.lines, 1):
            for pattern, desc in key_patterns:
                if re.search(pattern, line):
                    self.issues.append({
                        "type": "POLICY_VIOLATION",
                        "policy": "NO_HARDCODED_KEYS",
                        "description": desc,
                        "line": line_num,
                        "code_snippet": line.strip()[:80],
                        "severity": "CRITICAL",
                        "remediation": "Store keys in secure element, TPM, or secure provisioning service"
                    })

    def check_no_hardcoded_credentials(self):
        """Flag hardcoded usernames/passwords"""
        cred_patterns = [
            (r'password\s*=\s*"[^"]{4,}"', "Hardcoded password"),
            (r'username\s*=\s*"[^"]+"', "Hardcoded username"),
            (r'client_id\s*=\s*"([^"]+)"', "Hardcoded client ID"),
            (r'token\s*=\s*"[A-Za-z0-9\-_\.]{20,}"', "Hardcoded token"),
        ]
        
        for line_num, line in enumerate(self.lines, 1):
            for pattern, desc in cred_patterns:
                match = re.search(pattern, line)
                if match:
                    # Skip example values
                    value = match.group(1) if match.groups() else match.group(0)
                    if value.lower() not in ['example', 'test', 'demo', 'placeholder', 'change_me']:
                        self.issues.append({
                            "type": "POLICY_VIOLATION",
                            "policy": "NO_HARDCODED_CREDENTIALS",
                            "description": desc,
                            "line": line_num,
                            "code_snippet": line.strip()[:80],
                            "severity": "CRITICAL",
                            "remediation": "Use environment variables, secure vault, or secure provisioning"
                        })

    def check_strong_crypto_only(self):
        """Flag weak cryptographic algorithms"""
        weak_crypto = {
            'des_': 'DES (56-bit, broken)',
            '3des': '3DES (slow, weak)',
            'rc4': 'RC4 (broken)',
            'md5': 'MD5 (collision vulnerability)',
            'sha1': 'SHA-1 (deprecated, collision risk)',
        }
        
        for line_num, line in enumerate(self.lines, 1):
            for weak, desc in weak_crypto.items():
                if re.search(rf'\b{weak}\b', line.lower()):
                    self.issues.append({
                        "type": "POLICY_VIOLATION",
                        "policy": "STRONG_CRYPTO_ONLY",
                        "description": f"Weak crypto algorithm: {desc}",
                        "line": line_num,
                        "code_snippet": line.strip()[:80],
                        "severity": "CRITICAL",
                        "remediation": "Use AES-256, ChaCha20, or SHA-256 instead"
                    })

    def check_mutual_auth(self):
        """Check for mutual authentication requirement"""
        has_client_cert = False
        has_server_verify = False
        
        for line in self.lines:
            if 'client_cert' in line or 'client_key' in line or 'certificate' in line:
                has_client_cert = True
            if 'verify_peer' in line or 'check_hostname' in line:
                has_server_verify = True
        
        if not (has_client_cert and has_server_verify):
            self.issues.append({
                "type": "POLICY_VIOLATION",
                "policy": "MUTUAL_AUTH_REQUIRED",
                "description": "Mutual authentication not fully configured",
                "line": 1,
                "severity": "MEDIUM",
                "remediation": "Configure both client certificate and server verification"
            })