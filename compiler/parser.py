class ASTNode:
    def __init__(self, node_type, value=None, line=None):
        self.type = node_type
        self.value = value
        self.line = line
        self.children = []
        self.symbols = {}
        self.security_attrs = {}

    def add_child(self, child):
        self.children.append(child)
        return self

    def __repr__(self, level=0):
        indent = "  " * level
        result = f"{indent}{self.type}"
        if self.value:
            result += f": {self.value}"
        if self.security_attrs:
            result += f" [SEC: {self.security_attrs}]"
        result += "\n"
        for child in self.children:
            result += child.__repr__(level + 1)
        return result


class Parser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0

    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def consume(self, expected_type=None):
        token = self.peek()
        if token and (expected_type is None or token.type == expected_type):
            self.pos += 1
            return token
        return None

    def parse(self):
        """Parse tokens into AST with security-relevant nodes"""
        root = ASTNode("PROGRAM", line=1)
        
        while self.pos < len(self.tokens):
            token = self.peek()
            
            if token.type == 'PREPROC':
                root.add_child(self.parse_preprocessor())
            elif token.type == 'KEYWORD':
                if token.value in ['int', 'char', 'void', 'static', 'const']:
                    root.add_child(self.parse_declaration())
                elif token.value in ['if', 'while', 'for']:
                    root.add_child(self.parse_control_flow())
                elif token.value == 'return':
                    root.add_child(self.parse_return())
                else:
                    self.pos += 1
            elif token.type == 'IDENTIFIER':
                # Check for function call
                next_token = self.tokens[self.pos + 1] if self.pos + 1 < len(self.tokens) else None
                if next_token and next_token.type == 'PUNCTUATION' and next_token.value == '(':
                    root.add_child(self.parse_function_call())
                else:
                    root.add_child(self.parse_assignment())
            else:
                self.pos += 1
        
        return root

    def parse_preprocessor(self):
        token = self.consume('PREPROC')
        node = ASTNode("PREPROCESSOR", token.value, token.line)
        # Parse include/define content
        if self.peek() and self.peek().type in ['IDENTIFIER', 'STRING']:
            node.add_child(ASTNode("ARG", self.consume().value))
        return node

    def parse_declaration(self):
        type_token = self.consume('KEYWORD')
        node = ASTNode("DECLARATION", type_token.value, type_token.line)
        
        # Variable name
        name_token = self.consume('IDENTIFIER')
        if name_token:
            node.add_child(ASTNode("VARIABLE", name_token.value, name_token.line))
        
        # Optional assignment
        if self.peek() and self.peek().value == '=':
            self.consume('OPERATOR')
            value_token = self.consume()
            if value_token:
                node.add_child(ASTNode("INIT_VALUE", value_token.value, value_token.line))
        
        # Semicolon
        if self.peek() and self.peek().value == ';':
            self.consume('PUNCTUATION')
        
        return node

    def parse_function_call(self):
        name_token = self.consume('IDENTIFIER')
        node = ASTNode("FUNCTION_CALL", name_token.value, name_token.line)
        
        # Security annotation for crypto/protocol functions
        if name_token.value in ["mqtt_connect", "coap_send", "tls_handshake", "encrypt", "decrypt"]:
            node.security_attrs["requires_secure"] = True
        
        # Parse arguments
        if self.peek() and self.peek().value == '(':
            self.consume('PUNCTUATION')
            while self.peek() and self.peek().value != ')':
                arg_token = self.consume()
                if arg_token:
                    node.add_child(ASTNode("ARG", arg_token.value, arg_token.line))
                if self.peek() and self.peek().value == ',':
                    self.consume('PUNCTUATION')
            self.consume('PUNCTUATION')
        
        if self.peek() and self.peek().value == ';':
            self.consume('PUNCTUATION')
        
        return node

    def parse_control_flow(self):
        kw_token = self.consume('KEYWORD')
        node = ASTNode("CONTROL_FLOW", kw_token.value, kw_token.line)
        
        if self.peek() and self.peek().value == '(':
            self.consume('PUNCTUATION')
            # Parse condition (simplified)
            while self.peek() and self.peek().value != ')':
                node.add_child(ASTNode("CONDITION", self.consume().value))
            self.consume('PUNCTUATION')
        
        # Parse body (simplified)
        if self.peek() and self.peek().value == '{':
            self.consume('PUNCTUATION')
            body = ASTNode("BODY")
            while self.peek() and self.peek().value != '}':
                body.add_child(ASTNode("STATEMENT", self.consume().value))
            self.consume('PUNCTUATION')
            node.add_child(body)
        
        return node

    def parse_assignment(self):
        var_token = self.consume('IDENTIFIER')
        node = ASTNode("ASSIGNMENT", var_token.value, var_token.line)
        
        if self.peek() and self.peek().value == '=':
            self.consume('OPERATOR')
            val_token = self.consume()
            if val_token:
                node.add_child(ASTNode("VALUE", val_token.value, val_token.line))
        
        if self.peek() and self.peek().value == ';':
            self.consume('PUNCTUATION')
        
        return node

    def parse_return(self):
        token = self.consume('KEYWORD')
        node = ASTNode("RETURN", token.value, token.line)
        
        val_token = self.consume()
        if val_token and val_token.value != ';':
            node.add_child(ASTNode("VALUE", val_token.value, val_token.line))
        
        if self.peek() and self.peek().value == ';':
            self.consume('PUNCTUATION')
        
        return node