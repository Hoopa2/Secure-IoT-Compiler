#!/usr/bin/env python3
"""
Week 8 Deliverable: Data-Flow Analysis for Security
Tracks secret propagation and detects leaks
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compiler.lexer import Lexer
from compiler.parser import Parser
from compiler.symbol_table import SymbolTable
from compiler.dataflow import DataFlowAnalyzer

def main():
    print("=" * 70)
    print("WEEK 8 DELIVERABLE: Data-Flow Analysis")
    print("=" * 70)
    
    # Test code with secret propagation and leak
    test_code = '''
const char* API_KEY = "sk_test_4eC39HqLyjWDarjtT1zdp7dc";
const char* PASSWORD = "MySecretPass123";

void process() {
    char* temp = API_KEY;
    char* another = temp;
    
    // LEAK 1: Direct print of secret
    printf("API Key: %s\n", API_KEY);
    
    // LEAK 2: Print through propagated variable
    printf("Temp: %s\n", temp);
    
    // LEAK 3: Print through second propagation
    printf("Another: %s\n", another);
    
    // LEAK 4: Send over MQTT
    mqtt_publish("topic", PASSWORD);
}
'''
    
    print("\n[INPUT CODE]")
    print("-" * 50)
    print(test_code)
    print("-" * 50)
    
    # Run analysis
    symbol_table = SymbolTable()
    dataflow = DataFlowAnalyzer(test_code, symbol_table)
    leaks = dataflow.detect_leaks()
    
    print("\n[DATA-FLOW ANALYSIS RESULTS]")
    print("-" * 50)
    
    if leaks:
        print(f"Found {len(leaks)} security issues:\n")
        for leak in leaks:
            severity_color = "🔴" if leak.get("severity") == "CRITICAL" else "🟡"
            print(f"{severity_color} {leak['type']}: {leak['description']}")
            print(f"   Line {leak.get('line', '?')}: {leak.get('code_snippet', '')[:60]}")
            print()
    else:
        print("No data leaks detected.")
    
    print("\n[TAINT PROPAGATION CHAIN DEMO]")
    print("-" * 50)
    print("""
    API_KEY (secret source)
        ↓
    temp = API_KEY  (taint propagates)
        ↓
    another = temp  (taint propagates further)
        ↓
    printf(another)  (LEAK detected)
    """)
    
    print("\n" + "=" * 70)
    print("✅ WEEK 8 DELIVERABLE COMPLETE")
    print("   Data-flow analysis tracks:")
    print("   - Secret source identification")
    print("   - Taint propagation through assignments")
    print("   - Leak detection (print, network send)")
    print("=" * 70)

if __name__ == "__main__":
    main()