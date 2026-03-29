import re

class TaintNode:
    def __init__(self, name, line):
        self.name = name
        self.line = line
        self.sources = []  # Where this value came from
        self.is_tainted = False

class DataFlowAnalyzer:
    def __init__(self, code, symbol_table):
        self.code = code
        self.lines = code.split('\n')
        self.symbol_table = symbol_table
        self.taint_map = {}  # variable -> TaintNode
        self.issues = []

    def detect_leaks(self):
        """Detect secret data being leaked via output functions"""
        # First, identify secret variables
        self._mark_secret_sources()
        
        # Then track where they flow
        self._track_taint_propagation()
        
        # Finally, detect leaks
        self._detect_output_leaks()
        
        return self.issues

    def _mark_secret_sources(self):
        """Mark variables initialized with secret-looking values"""
        for line_num, line in enumerate(self.lines, 1):
            # Pattern: variable = "secret_value"
            match = re.search(r'(\w+)\s*=\s*"([^"]{10,})"', line)
            if match:
                var_name = match.group(1)
                secret_value = match.group(2)
                # Check if looks like a secret (has entropy)
                if re.search(r'[A-Z]{4,}', secret_value) or len(set(secret_value)) > 10:
                    self.symbol_table.mark_as_secret(var_name)
                    self.taint_map[var_name] = TaintNode(var_name, line_num)
                    self.taint_map[var_name].is_tainted = True
                    
                    self.issues.append({
                        "type": "SECRET_SOURCE",
                        "description": f"Potential secret assigned to '{var_name}'",
                        "line": line_num,
                        "code_snippet": line.strip()[:80],
                        "severity": "INFO"
                    })
            
            # Pattern: const char* secret = "..."
            match = re.search(r'const\s+char\s*\*\s*(\w+)\s*=\s*"([^"]+)"', line)
            if match:
                var_name = match.group(1)
                if 'secret' in var_name.lower() or 'key' in var_name.lower() or 'token' in var_name.lower():
                    self.symbol_table.mark_as_secret(var_name)
                    self.taint_map[var_name] = TaintNode(var_name, line_num)
                    self.taint_map[var_name].is_tainted = True

    def _track_taint_propagation(self):
        """Track how tainted data propagates through assignments"""
        for line_num, line in enumerate(self.lines, 1):
            # Assignment: dest = source
            match = re.search(r'(\w+)\s*=\s*(\w+)', line)
            if match:
                dest = match.group(1)
                source = match.group(2)
                
                if source in self.taint_map and self.taint_map[source].is_tainted:
                    if dest not in self.taint_map:
                        self.taint_map[dest] = TaintNode(dest, line_num)
                    self.taint_map[dest].is_tainted = True
                    self.taint_map[dest].sources.append(source)
                    self.symbol_table.mark_as_secret(dest)

    def _detect_output_leaks(self):
        """Detect secret data being printed/sent over network"""
        output_functions = ['printf', 'puts', 'fprintf', 'sprintf', 'snprintf', 
                           'mqtt_publish', 'coap_send', 'send', 'write', 'Serial.print']
        
        for line_num, line in enumerate(self.lines, 1):
            for func in output_functions:
                if re.search(rf'\b{func}\s*\(', line):
                    # Check if any secret variable is passed to output
                    for secret_var in self.symbol_table.get_all_secrets():
                        if secret_var.name in line:
                            self.issues.append({
                                "type": "DATA_LEAK",
                                "description": f"Secret '{secret_var.name}' leaked via {func}()",
                                "line": line_num,
                                "code_snippet": line.strip()[:80],
                                "severity": "CRITICAL"
                            })
                    
                    # Also check taint map
                    for var_name, taint in self.taint_map.items():
                        if taint.is_tainted and var_name in line:
                            self.issues.append({
                                "type": "DATA_LEAK",
                                "description": f"Tainted data '{var_name}' leaked via {func}()",
                                "line": line_num,
                                "code_snippet": line.strip()[:80],
                                "severity": "HIGH"
                            })