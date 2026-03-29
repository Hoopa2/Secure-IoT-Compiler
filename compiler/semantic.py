import re
from config import INSECURE_FUNCTIONS, WEAK_RANDOM_FUNCTIONS, STRONG_CIPHERS, WEAK_CIPHERS, STRONG_HASHES, WEAK_HASHES

class SemanticAnalyzer:
    def __init__(self, code, symbol_table):
        self.code = code
        self.lines = code.split('\n')
        self.symbol_table = symbol_table
        self.issues = []

    def analyze(self):
        """Run all semantic checks"""
        self.check_insecure_functions()
        self.check_weak_random()
        self.check_crypto_strength()
        self.check_protocol_security()
        self.check_missing_error_handling()
        self.check_buffer_overflow_risk()
        return self.issues

    def check_insecure_functions(self):
        for line_num, line in enumerate(self.lines, 1):
            for func in INSECURE_FUNCTIONS:
                pattern = rf'\b{func}\s*\('
                if re.search(pattern, line):
                    self.issues.append({
                        "type": "INSECURE_FUNCTION",
                        "description": f"Use of insecure function: {func}()",
                        "line": line_num,
                        "code_snippet": line.strip()[:80],
                        "suggestion": f"Replace {func}() with secure alternative (fgets, strncpy, snprintf)",
                        "severity": "HIGH"
                    })

    def check_weak_random(self):
        """Detect weak RNG usage - but NOT secure ones"""
        for line_num, line in enumerate(self.lines, 1):
            # Skip lines that contain secure random functions
            if 'esp_random' in line or 'getrandom' in line or 'RAND_bytes' in line:
                continue
                
            for rng in WEAK_RANDOM_FUNCTIONS:
                # Match exact word, not substring
                if re.search(rf'\b{re.escape(rng)}\b', line):
                    self.issues.append({
                        "type": "WEAK_RANDOM",
                        "description": f"Weak/predictable random number: {rng}",
                        "line": line_num,
                        "code_snippet": line.strip()[:80],
                        "suggestion": "Use cryptographically secure RNG (esp_random, getrandom, RAND_bytes)",
                        "severity": "CRITICAL"
                    })

    def check_crypto_strength(self):
        for line_num, line in enumerate(self.lines, 1):
            for weak_cipher in WEAK_CIPHERS:
                if weak_cipher in line:
                    self.issues.append({
                        "type": "WEAK_CRYPTO",
                        "description": f"Weak cipher algorithm: {weak_cipher}",
                        "line": line_num,
                        "code_snippet": line.strip()[:80],
                        "suggestion": f"Use {STRONG_CIPHERS[0]} or ChaCha20-Poly1305 instead",
                        "severity": "CRITICAL"
                    })
            
            for weak_hash in WEAK_HASHES:
                if re.search(rf'\b{weak_hash}\s*\(', line, re.IGNORECASE):
                    self.issues.append({
                        "type": "WEAK_HASH",
                        "description": f"Broken hash function: {weak_hash}",
                        "line": line_num,
                        "code_snippet": line.strip()[:80],
                        "suggestion": f"Use {STRONG_HASHES[0]} or SHA-256 instead",
                        "severity": "HIGH"
                    })

    def check_protocol_security(self):
        # Check for MQTT without TLS
        for line_num, line in enumerate(self.lines, 1):
            if 'mqtt://' in line and 'mqtts://' not in line and 'tls' not in line.lower():
                self.issues.append({
                    "type": "INSECURE_PROTOCOL",
                    "description": "MQTT without TLS - credentials and data sent in plaintext",
                    "line": line_num,
                    "code_snippet": line.strip()[:80],
                    "suggestion": "Use mqtts:// (MQTT over TLS) or add TLS configuration",
                    "severity": "CRITICAL"
                })
            
            if 'coap://' in line and 'coaps://' not in line:
                self.issues.append({
                    "type": "INSECURE_PROTOCOL",
                    "description": "CoAP without DTLS - no encryption or authentication",
                    "line": line_num,
                    "code_snippet": line.strip()[:80],
                    "suggestion": "Use coaps:// (CoAP over DTLS)",
                    "severity": "CRITICAL"
                })

    def check_missing_error_handling(self):
        """Check for crypto/network calls without error checking"""
        # Only check actual function CALLS, not declarations or includes
        crypto_calls = ['encrypt(', 'decrypt(', 'tls_connect(', 'ssl_connect(', 'mqtt_connect(', 'coap_send(']
        
        for line_num, line in enumerate(self.lines, 1):
            # Skip comments and include lines
            if line.strip().startswith('#include') or line.strip().startswith('//'):
                continue
            
            for call in crypto_calls:
                if call in line:
                    # Check if this is a function call (has parentheses with content)
                    # And not a function definition
                    if 'void ' + call.split('(')[0] in line:
                        continue  # This is a function definition, skip
                        
                    # Check next few lines for error handling
                    next_lines = self.lines[line_num:min(line_num+3, len(self.lines))]
                    has_error_check = any('if' in nl or 'return' in nl or 'ERROR' in nl.upper() or 'result' in nl for nl in next_lines)
                    
                    if not has_error_check:
                        self.issues.append({
                            "type": "MISSING_ERROR_HANDLING",
                            "description": f"Missing error check for {call}",
                            "line": line_num,
                            "code_snippet": line.strip()[:80],
                            "suggestion": "Check return value for errors",
                            "severity": "MEDIUM"
                        })
                    break  # Only report once per line

    def check_buffer_overflow_risk(self):
        for line_num, line in enumerate(self.lines, 1):
            # Check for fixed-size arrays with input functions
            if re.search(r'char\s+\w+\s*\[\s*\d+\s*\]', line):
                next_line = self.lines[line_num] if line_num < len(self.lines) else ""
                if 'gets' in next_line or 'scanf' in next_line and '%s' in next_line:
                    self.issues.append({
                        "type": "BUFFER_OVERFLOW",
                        "description": "Fixed-size buffer with unsafe input function",
                        "line": line_num,
                        "code_snippet": line.strip()[:80] + " ... " + next_line.strip()[:40],
                        "suggestion": "Use fgets with size limit or dynamic allocation",
                        "severity": "HIGH"
                    })