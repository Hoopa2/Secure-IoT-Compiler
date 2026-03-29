#!/usr/bin/env python3
"""
Week 11 Deliverable: Complete Test Suite for IoT Firmware Security
Location: tests/test_suite.py
"""

import sys
import os
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compiler.lexer import Lexer
from compiler.semantic import SemanticAnalyzer
from compiler.policy import PolicyEngine
from compiler.dataflow import DataFlowAnalyzer
from compiler.symbol_table import SymbolTable

# Test firmware files
TEST_FILES = {
    "test.c": "Original test firmware",
    "test2_insecure.c": "Complex insecure firmware (21 violations expected)",
    "test3_secure.c": "Secure firmware (0 violations expected)",
    "test4_authentication.c": "Authentication test cases"
}

class SecurityTestSuite:
    def __init__(self):
        self.results = []
        self.input_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "input")
    
    def run_all_tests(self):
        """Run all test files"""
        print("=" * 80)
        print("SECURITY TEST SUITE FOR IoT FIRMWARE")
        print("=" * 80)
        
        for filename, description in TEST_FILES.items():
            filepath = os.path.join(self.input_dir, filename)
            if os.path.exists(filepath):
                self.run_single_test(filepath, description)
            else:
                print(f"\n⚠️  File not found: {filename}")
        
        self.print_summary()
        self.generate_report()
    
    def run_single_test(self, filepath, description):
        """Run security analysis on a single file"""
        with open(filepath, 'r') as f:
            code = f.read()
        
        print(f"\n{'='*80}")
        print(f"TEST: {os.path.basename(filepath)}")
        print(f"Description: {description}")
        print(f"{'='*80}")
        
        # Run all security checks
        results = {
            "file": os.path.basename(filepath),
            "secrets": [],
            "insecure_functions": [],
            "weak_random": [],
            "policy_violations": [],
            "data_leaks": []
        }
        
        # Lexer checks
        lexer = Lexer(code)
        results["secrets"] = lexer.detect_secrets()
        results["insecure_functions"] = lexer.detect_insecure_functions()
        results["weak_random"] = lexer.detect_weak_random()
        
        # Policy checks
        symbol_table = SymbolTable()
        policy = PolicyEngine(code, symbol_table, None)
        results["policy_violations"] = policy.enforce()
        
        # Data-flow checks
        dataflow = DataFlowAnalyzer(code, symbol_table)
        results["data_leaks"] = dataflow.detect_leaks()
        
        # Calculate totals
        total_issues = (
            len(results["secrets"]) +
            len(results["insecure_functions"]) +
            len(results["weak_random"]) +
            len(results["policy_violations"]) +
            len(results["data_leaks"])
        )
        
        results["total_issues"] = total_issues
        results["passed"] = total_issues == 0
        
        # Print results
        print(f"\n[RESULTS]")
        print(f"  Hardcoded secrets:     {len(results['secrets'])}")
        print(f"  Insecure functions:    {len(results['insecure_functions'])}")
        print(f"  Weak random:           {len(results['weak_random'])}")
        print(f"  Policy violations:     {len(results['policy_violations'])}")
        print(f"  Data leaks:            {len(results['data_leaks'])}")
        print(f"  TOTAL ISSUES:          {total_issues}")
        print(f"  VERDICT:               {'✅ PASS' if results['passed'] else '❌ FAIL'}")
        
        # Show sample issues
        if results['secrets']:
            print(f"\n  Sample secrets:")
            for s in results['secrets'][:2]:
                print(f"    - Line {s.get('line', '?')}: {s.get('description', '')[:50]}")
        
        if results['policy_violations']:
            print(f"\n  Sample policy violations:")
            for v in results['policy_violations'][:2]:
                print(f"    - {v.get('description', '')[:60]}")
        
        self.results.append(results)
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 80)
        print("TEST SUMMARY")
        print("=" * 80)
        
        passed = sum(1 for r in self.results if r["passed"])
        failed = len(self.results) - passed
        total_issues = sum(r["total_issues"] for r in self.results)
        
        print(f"\nTotal tests:    {len(self.results)}")
        print(f"Passed:         {passed}")
        print(f"Failed:         {failed}")
        print(f"Pass rate:      {(passed/len(self.results))*100:.1f}%")
        print(f"Total issues:   {total_issues}")
        
        print("\n[BREAKDOWN BY TEST]")
        for r in self.results:
            status = "✅" if r["passed"] else "❌"
            print(f"  {status} {r['file']}: {r['total_issues']} issues")
    
    def generate_report(self):
        """Generate JSON report"""
        os.makedirs("output", exist_ok=True)
        report_path = "output/test_suite_report.json"
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_tests": len(self.results),
                "passed": sum(1 for r in self.results if r["passed"]),
                "failed": sum(1 for r in self.results if not r["passed"]),
                "total_issues": sum(r["total_issues"] for r in self.results)
            },
            "test_results": self.results
        }
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📁 Report saved: {report_path}")

def main():
    suite = SecurityTestSuite()
    suite.run_all_tests()
    
    print("\n" + "=" * 80)
    print("✅ TEST SUITE COMPLETE")
    print("   Validated against 4 IoT firmware samples")
    print("=" * 80)

if __name__ == "__main__":
    main()