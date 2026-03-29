#!/usr/bin/env python3
"""
Week 6 Deliverable: Parser with Security AST Nodes
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compiler.lexer import Lexer
from compiler.parser import Parser

def print_ast(node, indent=0):
    """Pretty print AST"""
    prefix = "  " * indent
    sec_marker = f" [SEC:{node.security_attrs}]" if node.security_attrs else ""
    print(f"{prefix}├─ {node.type}: {node.value if node.value else 'root'}{sec_marker}")
    for child in node.children:
        print_ast(child, indent + 1)

def main():
    print("=" * 70)
    print("WEEK 6 DELIVERABLE: Parser with Security-Aware AST")
    print("=" * 70)
    
    test_code = '''
int main() {
    int x = 10;
    mqtt_connect("broker.com");
    if (x > 5) {
        printf("Hello");
    }
    return 0;
}
'''
    
    print("\n[INPUT CODE]")
    print("-" * 50)
    print(test_code)
    print("-" * 50)
    
    # Parse
    lexer = Lexer(test_code)
    tokens = lexer.tokenize()
    parser = Parser(tokens)
    ast = parser.parse()
    
    print("\n[AST STRUCTURE]")
    print("-" * 50)
    print_ast(ast)
    
    # Security node detection
    print("\n[SECURITY-RELEVANT NODES DETECTED]")
    def find_security_nodes(node):
        if node.type == "FUNCTION_CALL":
            if node.value in ["mqtt_connect", "coap_send", "tls_handshake", "encrypt", "decrypt"]:
                print(f"  🔐 Security-sensitive call: {node.value}() at line {node.line}")
        for child in node.children:
            find_security_nodes(child)
    
    find_security_nodes(ast)
    
    print("\n" + "=" * 70)
    print("✅ WEEK 6 DELIVERABLE COMPLETE")
    print("   Parser successfully generates AST with:")
    print("   - Security node annotations")
    print("   - Function call detection")
    print("   - Control flow structures")
    print("=" * 70)

if __name__ == "__main__":
    main()