import re
from config import SECRET_PATTERNS, INSECURE_FUNCTIONS, WEAK_RANDOM_FUNCTIONS, STRONG_RANDOM_FUNCTIONS

class Token:
    def __init__(self, token_type, value, line, column):
        self.type = token_type
        self.value = value
        self.line = line
        self.column = column

    def __repr__(self):
        return f"Token({self.type}, '{self.value}', L{self.line}:C{self.column})"


class Lexer:
    def __init__(self, code):
        self.code = code
        self.lines = code.split('\n')
        self.tokens = []
        self.secret_issues = []
        self.line = 1
        self.column = 1

    def tokenize(self):
        """Full C/C++ tokenization with security annotations"""
        # Token patterns: keywords, identifiers, literals, operators
        token_specs = [
            ('NUMBER',    r'\b\d+(?:\.\d+)?\b'),
            ('HEX_NUM',   r'\b0x[0-9A-Fa-f]+\b'),
            ('STRING',    r'"(?:\\.|[^"\\])*"'),
            ('CHAR',      r"'(?:\\.|[^'\\])*'"),
            ('KEYWORD',   r'\b(?:if|else|while|for|return|int|char|void|static|const|struct|enum|typedef|sizeof|include|define|ifdef|endif)\b'),
            ('IDENTIFIER', r'\b[A-Za-z_][A-Za-z0-9_]*\b'),
            ('OPERATOR',  r'[+\-*/%=<>!&|^~?:]|==|!=|<=|>=|&&|\|\|'),
            ('PUNCTUATION', r'[\(\)\{\}\[\];,.]'),
            ('PREPROC',   r'#[A-Za-z_][A-Za-z0-9_]*'),
            ('WHITESPACE', r'\s+'),
            ('COMMENT',   r'//[^\n]*|/\*.*?\*/'),
            ('MISMATCH',  r'.'),
        ]
        
        token_regex = '|'.join(f'(?P<{name}>{pattern})' for name, pattern in token_specs)
        pos = 0
        line = 1
        line_start = 0
        
        for match in re.finditer(token_regex, self.code, re.DOTALL):
            kind = match.lastgroup
            value = match.group()
            col = match.start() - line_start + 1
            
            if kind == 'WHITESPACE':
                if '\n' in value:
                    line += value.count('\n')
                    line_start = match.end() - (value.rfind('\n') if '\n' in value else 0) - 1
                continue
            elif kind == 'COMMENT':
                # Still track line count in comments
                line += value.count('\n')
                if '\n' in value:
                    line_start = match.end() - (value.rfind('\n') if '\n' in value else 0) - 1
                continue
            elif kind == 'MISMATCH':
                self.tokens.append(Token('ERROR', value, line, col))
            else:
                self.tokens.append(Token(kind, value, line, col))
        
        return self.tokens

    def detect_secrets(self):
        """Detect hardcoded secrets using regex patterns"""
        issues = []
        for line_num, line in enumerate(self.lines, 1):
            # Skip lines that are function calls or function definitions
            if '(' in line and ')' in line:
                # This is a function call - likely not a hardcoded secret
                continue
            
            for pattern, description in SECRET_PATTERNS:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    issues.append({
                        "type": "HARDCODED_SECRET",
                        "description": description,
                        "line": line_num,
                        "match": match.group(0)[:50],
                        "severity": "CRITICAL"
                    })
        self.secret_issues = issues
        return issues

    def detect_insecure_functions(self):
        """Flag insecure C functions"""
        issues = []
        for line_num, line in enumerate(self.lines, 1):
            for func in INSECURE_FUNCTIONS:
                if re.search(rf'\b{func}\s*\(', line):
                    issues.append({
                        "type": "INSECURE_FUNCTION",
                        "description": f"Use of insecure function: {func}()",
                        "line": line_num,
                        "suggestion": f"Replace with secure alternative",
                        "severity": "HIGH"
                    })
        return issues

    def detect_weak_random(self):
        """Detect weak RNG usage"""
        issues = []
        for line_num, line in enumerate(self.lines, 1):
            for rng in WEAK_RANDOM_FUNCTIONS:
                if rng in line:
                    issues.append({
                        "type": "WEAK_RANDOM",
                        "description": f"Weak random number generator: {rng}",
                        "line": line_num,
                        "suggestion": "Use esp_random(), getrandom(), or RAND_bytes()",
                        "severity": "HIGH"
                    })
        return issues