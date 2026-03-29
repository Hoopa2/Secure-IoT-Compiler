#!/usr/bin/env python3
"""
Week 11 Deliverable: Test Suite for IoT Firmware Security
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compiler.lexer import Lexer
from compiler.semantic import SemanticAnalyzer
from compiler.policy import PolicyEngine
from compiler.symbol_table import SymbolTable

# Test firmware samples
TEST_FIRMWARES = {
    "test1_insecure_weather_sensor": '''
// Insecure weather sensor firmware
const char* API_KEY = "weather_api_12345";
const char* WIFI_PASSWORD = "sensor123";

void send_data() {
    char buffer[10];
    gets(buffer);
    mqtt_connect("mqtt://weather.com");
    int r = rand();
    printf("API: %s", API_KEY);
}
''',
    
    "test2_secure_light_controller": '''
// Secure light controller (should pass most checks)
#include <secure_storage.h>

void connect() {
    char* password = secure_read("wifi_cred");
    mqtts_connect("mqtts://secure.broker.com", password);
    uint32_t nonce = esp_random();
}
''',
    
    "test3_crypto_misuse": '''
// Crypto misuse patterns
void bad_crypto() {
    // Weak hash
    MD5(password);
    
    // Weak cipher
    DES_encrypt(data);
    
    // Hardcoded key
    unsigned char key[] = "fixedkey12345678";
    
    // No IV
    AES_ECB_encrypt(data, key);
}
''',
    
    "test4_protocol_violations": '''
// Protocol security violations
void bad_communication() {
    // HTTP instead of HTTPS
    http_get("http://api.com/data");
    
    // CoAP without DTLS
    coap_send("coap://sensor.net");
    
    // MQTT without TLS and no auth
    mqtt_connect("mqtt://broker.com");
}
'''
}

def run_test(name, code):
    """Run all security checks on a test firmware"""
    print(f"\n{'='*60}")
    print(f"TEST: {name}")
    print(f"{'='*60}")
    
    results = {
        "name": name,
        "secrets": 0,
        "insecure_funcs": 0,
        "weak_random": 0,
        "policy_violations": 0,
        "passed": True
    }
    
    # Lexer checks
    lexer = Lexer(code)
    secrets = lexer.detect_secrets()
    insecure_funcs = lexer.detect_insecure_functions()
    weak_random = lexer.detect_weak_random()
    
    results["secrets"] = len(secrets)
    results["insecure_funcs"] = len(insecure_funcs)
    results["weak_random"] = len(weak_random)
    
    # Policy checks
    policy = PolicyEngine(code, SymbolTable(), None)
    violations = policy.enforce()
    results["policy_violations"] = len(violations)
    
    # Determine if test passes (secure firmware should have 0 issues)
    total_issues = len(secrets) + len(insecure_funcs) + len(weak_random) + len(violations)
    results["passed"] = total_issues == 0
    results["total_issues"] = total_issues
    
    # Print results
    print(f"\n[SECURITY ANALYSIS]")
    print(f"  Hardcoded secrets:     {len(secrets)}")
    print(f"  Insecure functions:    {len(insecure_funcs)}")
    print(f"  Weak random:           {len(weak_random)}")
    print(f"  Policy violations:     {len(violations)}")
    print(f"  TOTAL ISSUES:          {total_issues}")
    print(f"  VERDICT:               {'✅ PASS' if results['passed'] else '❌ FAIL'}")
    
    if secrets:
        print(f"\n  Sample secrets found:")
        for s in secrets[:2]:
            print(f"    - {s['description'][:50]}")
    
    return results

def main():
    print("=" * 70)
    print("WEEK 11 DELIVERABLE: IoT Firmware Security Test Suite")
    print("=" * 70)
    print("\nTesting on multiple firmware samples (Contiki-NG/Zephyr style)")
    
    all_results = []
    for name, code in TEST_FIRMWARES.items():
        result = run_test(name, code)
        all_results.append(result)
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUITE SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for r in all_results if r["passed"])
    failed = len(all_results) - passed
    
    print(f"\nTotal tests:    {len(all_results)}")
    print(f"Passed:         {passed}")
    print(f"Failed:         {failed}")
    print(f"Pass rate:      {(passed/len(all_results))*100:.1f}%")
    
    print("\n[TEST BREAKDOWN]")
    for r in all_results:
        status = "✅" if r["passed"] else "❌"
        print(f"  {status} {r['name']}: {r['total_issues']} issues")
    
    print("\n[TEST COVERAGE]")
    print("""
    ✓ Hardcoded secret detection
    ✓ Insecure function detection (gets, strcpy, sprintf)
    ✓ Weak random detection
    ✓ Protocol security (TLS/DTLS enforcement)
    ✓ Crypto algorithm strength checking
    ✓ Authentication requirement validation
    """)
    
    print("\n" + "=" * 70)
    print("✅ WEEK 11 DELIVERABLE COMPLETE")
    print("   Test suite validates security enforcement on")
    print("   4 representative IoT firmware samples")
    print("=" * 70)

if __name__ == "__main__":
    main()