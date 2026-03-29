# ============================================================================
# SECURITY POLICIES CONFIGURATION
# ============================================================================

# Master policy switches
SECURITY_POLICIES = {
    "NO_HARDCODED_KEYS": True,
    "TLS_REQUIRED": True,
    "NO_WEAK_RANDOM": True,
    "NO_INSECURE_FUNCTIONS": True,
    "NO_HARDCODED_CREDENTIALS": True,
    "DTLS_REQUIRED_FOR_COAP": True,
    "STRONG_CRYPTO_ONLY": True,
    "MUTUAL_AUTH_REQUIRED": False,
}

# Insecure C functions to flag
INSECURE_FUNCTIONS = [
    "gets", "strcpy", "strcat", "sprintf", "vsprintf",
    "scanf", "sscanf", "fscanf", "memcpy", "strlen"
]

# Weak random number generators
WEAK_RANDOM_FUNCTIONS = [
    "rand()", "random()", "srand()", "rand_r()"
]

# Strong random (allowed)
STRONG_RANDOM_FUNCTIONS = [
    "esp_random()", "getrandom()", "RAND_bytes()"
]

# Secret patterns (regex)
SECRET_PATTERNS = [
    # Generic hardcoded secrets - ONLY flag if there's an assignment with = sign
    (r'(api[_-]?key|API[_-]?KEY)\s*=\s*["\']([A-Za-z0-9+/=]{20,})["\']', "Hardcoded API key"),
    (r'(secret|SECRET)\s*=\s*["\']([A-Za-z0-9]{16,})["\']', "Hardcoded secret token"),
    (r'(password|PASSWORD|passwd)\s*=\s*["\']([^"\']{4,})["\']', "Hardcoded password"),
    (r'(token|TOKEN|jwt|JWT)\s*=\s*["\']([A-Za-z0-9\-_.]{20,})["\']', "Hardcoded token/JWT"),
    (r'=\s*"-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----', "Embedded private key"),
    (r'0x[0-9A-Fa-f]{16,}', "Suspicious long hex constant (possible key)"),
    (r'aws[_-]?access[_-]?key[_-]?id\s*=\s*["\']([A-Z0-9]{16,})["\']', "AWS Access Key"),
    
    # DO NOT flag function parameters or function names
    # The patterns above require an = sign before the quoted string
]

# Crypto algorithm strength requirements
STRONG_CIPHERS = ["AES-256", "ChaCha20-Poly1305", "AES-128"]
WEAK_CIPHERS = ["DES", "3DES", "RC4", "Blowfish", "AES-64"]
STRONG_HASHES = ["SHA-256", "SHA-3", "BLAKE2", "SHA-512"]
WEAK_HASHES = ["MD5", "SHA-1"]

# IoT protocol patterns requiring TLS/DTLS
PROTOCOL_REQUIREMENTS = {
    "mqtt://": {"required": "TLS", "secure_pattern": "mqtts://", "message": "MQTT without TLS"},
    "coap://": {"required": "DTLS", "secure_pattern": "coaps://", "message": "CoAP without DTLS"},
    "http://": {"required": "TLS", "secure_pattern": "https://", "message": "HTTP without TLS"},
}

# Resource constraints for energy-aware optimization
ENERGY_PROFILES = {
    "ultra_low_power": {"max_crypto_ops": 100, "prefer_lightweight": True, "logging_level": "ERROR"},
    "battery_operated": {"max_crypto_ops": 1000, "prefer_lightweight": True, "logging_level": "WARNING"},
    "mains_powered": {"max_crypto_ops": 10000, "prefer_lightweight": False, "logging_level": "INFO"},
}
DEFAULT_ENERGY_PROFILE = "battery_operated"