#!/usr/bin/env python3
"""
Week 9 Deliverable: Policy Enforcement Engine
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compiler.policy import PolicyEngine
from compiler.symbol_table import SymbolTable
from compiler.parser import Parser
from compiler.lexer import Lexer

def main():
    print("=" * 70)
    print("WEEK 9 DELIVERABLE: Policy Enforcement Engine")
    print("=" * 70)
    
    # Test code violating multiple policies
    test_code = '''
// VIOLATION 1: MQTT without TLS
mqtt_connect("mqtt://broker.com");

// VIOLATION 2: CoAP without DTLS  
coap_send("coap://sensor.net");

// VIOLATION 3: Hardcoded key
const char* aes_key = "0123456789ABCDEF0123456789ABCDEF";

// VIOLATION 4: Hardcoded credential
const char* mqtt_password = "admin123";

// VIOLATION 5: Weak crypto
DES_cbc_encrypt(...);

// VIOLATION 6: No authentication
mqtt_connect("broker.com");  // No username/password/cert
'''
    
    print("\n[INPUT CODE WITH POLICY VIOLATIONS]")
    print("-" * 50)
    print(test_code)
    print("-" * 50)
    
    # Run policy enforcement
    symbol_table = SymbolTable()
    parser = Parser([])
    policy = PolicyEngine(test_code, symbol_table, None)
    violations = policy.enforce()
    
    print("\n[POLICY ENFORCEMENT RESULTS]")
    print("-" * 50)
    print(f"Total policy violations: {len(violations)}\n")
    
    # Group by severity
    critical = [v for v in violations if v.get("severity") == "CRITICAL"]
    high = [v for v in violations if v.get("severity") == "HIGH"]
    medium = [v for v in violations if v.get("severity") == "MEDIUM"]
    
    print(f"🔴 CRITICAL: {len(critical)}")
    for v in critical[:3]:
        print(f"   - {v.get('description', '')[:70]}")
    
    print(f"\n🟠 HIGH: {len(high)}")
    for v in high[:3]:
        print(f"   - {v.get('description', '')[:70]}")
    
    print(f"\n🟡 MEDIUM: {len(medium)}")
    for v in medium[:3]:
        print(f"   - {v.get('description', '')[:70]}")
    
    print("\n[POLICY DEFINITIONS]")
    print("-" * 50)
    print("""
    ┌─────────────────────────────────────────────────────────────┐
    │  POLICY NAME              │  DESCRIPTION                    │
    ├─────────────────────────────────────────────────────────────┤
    │  TLS_REQUIRED             │  All MQTT must use TLS          │
    │  DTLS_REQUIRED_FOR_COAP   │  All CoAP must use DTLS         │
    │  NO_HARDCODED_KEYS        │  No cryptographic keys in code  │
    │  NO_HARDCODED_CREDENTIALS │  No passwords in code           │
    │  STRONG_CRYPTO_ONLY       │  No DES, MD5, SHA-1             │
    │  MUTUAL_AUTH_REQUIRED     │  Client+server auth required    │
    └─────────────────────────────────────────────────────────────┘
    """)
    
    print("\n" + "=" * 70)
    print("✅ WEEK 9 DELIVERABLE COMPLETE")
    print("   Policy engine enforces:")
    print("   - Protocol security (TLS/DTLS)")
    print("   - No hardcoded secrets")
    print("   - Strong cryptography only")
    print("=" * 70)

if __name__ == "__main__":
    main()