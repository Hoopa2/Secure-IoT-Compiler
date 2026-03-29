import re
from config import ENERGY_PROFILES, DEFAULT_ENERGY_PROFILE

class Transformer:
    def __init__(self, code, energy_profile=DEFAULT_ENERGY_PROFILE):
        self.code = code
        self.energy_profile = energy_profile
        self.transformations_applied = []
        self.secure_code = code

    def transform(self):
        """Apply all security and energy-aware transformations"""
        self._replace_insecure_functions()
        self._add_bounds_checks()
        self._secure_random_generation()
        self._enforce_tls_upgrade()
        self._apply_energy_optimizations()
        self._add_error_handling()
        
        return self.secure_code

    def _replace_insecure_functions(self):
        """Replace dangerous functions with safe alternatives"""
        replacements = [
            (r'\bgets\s*\(', 'fgets(', 'gets -> fgets'),
            (r'\bstrcpy\s*\(', 'strncpy(', 'strcpy -> strncpy'),
            (r'\bsprintf\s*\(', 'snprintf(', 'sprintf -> snprintf'),
            (r'\bstrcat\s*\(', 'strncat(', 'strcat -> strncat'),
            (r'\bscanf\s*\(', 'fgets(', 'scanf -> fgets'),
        ]
        
        for pattern, replacement, desc in replacements:
            if re.search(pattern, self.secure_code):
                self.secure_code = re.sub(pattern, replacement, self.secure_code)
                self.transformations_applied.append(desc)

    def _add_bounds_checks(self):
        """Add buffer size checks for array accesses"""
        # Find array declarations and add size tracking
        array_pattern = r'(\w+)\s+(\w+)\s*\[\s*(\d+)\s*\]'
        
        def add_bound_check(match):
            array_type = match.group(1)
            array_name = match.group(2)
            array_size = match.group(3)
            return f"{array_type} {array_name}[{array_size}]; /* size: {array_size} */"
        
        self.secure_code = re.sub(array_pattern, add_bound_check, self.secure_code)
        self.transformations_applied.append("Added buffer size tracking")

    def _secure_random_generation(self):
        """Replace weak rand() with secure alternatives"""
        if 'rand()' in self.secure_code or 'random()' in self.secure_code:
            # Add secure random function definition
            secure_random_code = '''
// [TRANSFORMER] Replaced weak random with secure version
#include <stdint.h>
#ifdef ESP_PLATFORM
    #define SECURE_RANDOM() esp_random()
#elif defined(__linux__)
    #include <sys/random.h>
    #define SECURE_RANDOM() (getrandom(&(uint32_t){0}, 4, 0) == 4 ? *(uint32_t*)&(uint32_t){0} : rand())
#else
    #warning "No secure random source available, using fallback"
    #define SECURE_RANDOM() rand()
#endif
'''
            # Replace rand() calls
            self.secure_code = re.sub(r'\brand\(\s*\)', 'SECURE_RANDOM()', self.secure_code)
            self.secure_code = secure_random_code + "\n" + self.secure_code
            self.transformations_applied.append("Replaced weak random with secure RNG")

    def _enforce_tls_upgrade(self):
        """Upgrade plaintext protocols to secure versions"""
        # MQTT upgrade
        self.secure_code = re.sub(r'mqtt://', 'mqtts://', self.secure_code)
        # CoAP upgrade
        self.secure_code = re.sub(r'coap://', 'coaps://', self.secure_code)
        # HTTP upgrade
        self.secure_code = re.sub(r'http://(?!localhost)', 'https://', self.secure_code)
        
        if 'mqtt://' in self.code or 'coap://' in self.code:
            self.transformations_applied.append("Upgraded protocols to secure versions (TLS/DTLS)")

    def _apply_energy_optimizations(self):
        """Apply energy-aware transformations based on profile"""
        profile = ENERGY_PROFILES.get(self.energy_profile, ENERGY_PROFILES[DEFAULT_ENERGY_PROFILE])
        
        if profile.get("prefer_lightweight", False):
            # Replace heavy crypto with lightweight alternatives for low-power devices
            replacements = [
                (r'AES-256-CBC', 'ChaCha20', 'Heavy AES-256 replaced with ChaCha20'),
                (r'RSA-2048', 'ECC-256', 'RSA replaced with ECC for lower power'),
            ]
            for pattern, replacement, desc in replacements:
                if pattern.lower() in self.secure_code.lower():
                    self.secure_code = re.sub(pattern, replacement, self.secure_code, flags=re.IGNORECASE)
                    self.transformations_applied.append(desc)
        
        # Add logging level configuration
        log_level = profile.get("logging_level", "INFO")
        log_config = f'\n// [ENERGY] Logging level set to {log_level} for {self.energy_profile} profile\n'
        self.secure_code = log_config + self.secure_code
        self.transformations_applied.append(f"Configured logging level: {log_level}")

    def _add_error_handling(self):
        """Add error handling for security-critical operations"""
        # Add error checking for crypto operations
        crypto_pattern = r'(encrypt|decrypt|tls_handshake|ssl_connect)\s*\([^;]+\);'
        
        def add_error_check(match):
            original = match.group(0)
            func_name = match.group(1)
            return f'''{original}
    if ({func_name}_result < 0) {{
        // [TRANSFORMER] Added error handling for {func_name}
        log_error("{func_name} failed");
        return -1;
    }}'''
        
        self.secure_code = re.sub(crypto_pattern, add_error_check, self.secure_code)
        
        if 'encrypt' in self.code or 'decrypt' in self.code:
            self.transformations_applied.append("Added error handling for crypto operations")

    def get_report(self):
        """Return summary of transformations applied"""
        report = "\n=== TRANSFORMATIONS APPLIED ===\n"
        for i, transform in enumerate(self.transformations_applied, 1):
            report += f"{i}. {transform}\n"
        report += f"\nEnergy Profile: {self.energy_profile}\n"
        return report