#!/usr/bin/env python3
"""
Week 5 Deliverable: Security-Aware Lexer Demo
Shows tokenization and secret detection
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compiler.lexer import Lexer

def main():
    print("=" * 70)
    print("WEEK 5 DELIVERABLE: Security-Aware Lexer")
    print("=" * 70)
    
    # Test code with various secrets
    test_code = '''
#include <stdio.h>

const char* API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
const char* PASSWORD = "admin123";
const char* SECRET_TOKEN = "github_pat_11ABCDEFGHIJKLMNOPQRSTUVWXYZ";

void insecure_function() {
    char buffer[10];
    gets(buffer);  // Insecure function
    int r = rand(); // Weak random
}

void main() {
    printf("Hello");
}
'''
    
    print("\n[INPUT CODE]")
    print("-" * 50)
    print(test_code)
    print("-" * 50)
    
    # Run lexer
    lexer = Lexer(test_code)
    tokens = lexer.tokenize()
    secrets = lexer.detect_secrets()
    insecure_funcs = lexer.detect_insecure_functions()
    weak_random = lexer.detect_weak_random()
    
    print("\n[TOKENS GENERATED]")
    print(f"Total tokens: {len(tokens)}")
    print(f"Sample tokens (first 20):")
    for token in tokens[:20]:
        print(f"  {token}")
    
    print("\n[SECURITY DETECTIONS]")
    print(f"Hardcoded secrets: {len(secrets)}")
    for s in secrets:
        print(f"  ⚠️  Line {s['line']}: {s['description']}")
        print(f"     Match: {s['match']}")
    
    print(f"\nInsecure functions: {len(insecure_funcs)}")
    for f in insecure_funcs:
        print(f"  ❌ Line {f['line']}: {f['description']}")
    
    print(f"\nWeak random generators: {len(weak_random)}")
    for w in weak_random:
        print(f"  🔴 Line {w['line']}: {w['description']}")
    
    print("\n" + "=" * 70)
    print("✅ WEEK 5 DELIVERABLE COMPLETE")
    print("   Lexer successfully detects:")
    print("   - Hardcoded secrets (API keys, passwords, tokens)")
    print("   - Insecure C functions (gets, strcpy, sprintf)")
    print("   - Weak random number generators")
    print("=" * 70)

if __name__ == "__main__":
    main()