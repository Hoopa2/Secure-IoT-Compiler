#!/usr/bin/env python3
"""
Week 7 Deliverable: Symbol Table with Security Attributes
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compiler.lexer import Lexer
from compiler.parser import Parser
from compiler.symbol_table import SymbolTable

def extract_symbols_from_ast(node, symbol_table):
    """Extract symbols from AST"""
    if node.type == "DECLARATION":
        for child in node.children:
            if child.type == "VARIABLE":
                symbol_table.add(child.value, node.value, node.line or 1)
    elif node.type == "FUNCTION_CALL":
        symbol_table.add(node.value, "FUNCTION", node.line or 1)
    elif node.type == "FUNCTION" or (node.type == "IDENTIFIER" and node.parent_type == "function"):
        pass
    
    for child in node.children:
        extract_symbols_from_ast(child, symbol_table)

def main():
    print("=" * 70)
    print("WEEK 7 DELIVERABLE: Symbol Table with Security Attributes")
    print("=" * 70)
    
    test_code = '''
const char* SECRET_KEY = "super_secret_12345678";
int counter = 0;

void secure_send(char* data) {
    encrypt(data);
}

void connect_mqtt() {
    char buffer[100];
    mqtt_connect("broker");
}

int main() {
    int x = 10;
    return 0;
}
'''
    
    print("\n[INPUT CODE]")
    print("-" * 50)
    print(test_code)
    print("-" * 50)
    
    # Parse and build symbol table
    lexer = Lexer(test_code)
    tokens = lexer.tokenize()
    parser = Parser(tokens)
    ast = parser.parse()
    
    symbol_table = SymbolTable()
    extract_symbols_from_ast(ast, symbol_table)
    
    # Mark secrets
    symbol_table.mark_as_secret("SECRET_KEY")
    
    print("\n[SYMBOL TABLE]")
    print("-" * 50)
    print(symbol_table.display())
    
    print("\n[SECURITY ATTRIBUTES]")
    print("-" * 50)
    secrets = symbol_table.get_all_secrets()
    print(f"Marked as secret: {[s.name for s in secrets]}")
    
    print(f"\nLookup 'SECRET_KEY': {symbol_table.lookup('SECRET_KEY')}")
    print(f"Is 'SECRET_KEY' secret? {symbol_table.is_secret('SECRET_KEY')}")
    print(f"Is 'counter' secret? {symbol_table.is_secret('counter')}")
    
    print("\n" + "=" * 70)
    print("✅ WEEK 7 DELIVERABLE COMPLETE")
    print("   Symbol table supports:")
    print("   - Scope management")
    print("   - Secret taint marking")
    print("   - Type tracking")
    print("=" * 70)

if __name__ == "__main__":
    main()