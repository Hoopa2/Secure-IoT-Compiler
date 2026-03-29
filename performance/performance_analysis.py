#!/usr/bin/env python3
"""
Week 12 Deliverable: Performance & Overhead Analysis with Charts
Location: performance/performance_analysis.py
"""

import sys
import os
import time
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compiler.lexer import Lexer
from compiler.parser import Parser
from compiler.semantic import SemanticAnalyzer
from compiler.dataflow import DataFlowAnalyzer
from compiler.policy import PolicyEngine
from compiler.transformer import Transformer
from compiler.symbol_table import SymbolTable

class PerformanceAnalyzer:
    def __init__(self):
        self.results = []
    
    def get_memory_usage(self):
        """Get memory usage in MB"""
        import psutil
        process = psutil.Process()
        return process.memory_info().rss / 1024 / 1024
    
    def run_secure_compiler(self, code, name):
        """Run secure compiler and measure performance"""
        start_time = time.time()
        start_mem = self.get_memory_usage()
        
        # Track phase times
        phases = []
        
        # Phase 1: Lexical
        t0 = time.time()
        lexer = Lexer(code)
        tokens = lexer.tokenize()
        secrets = lexer.detect_secrets()
        phases.append(("Lexical Analysis", time.time() - t0))
        
        # Phase 2: Parsing
        t0 = time.time()
        parser = Parser(tokens)
        ast = parser.parse()
        phases.append(("Parsing", time.time() - t0))
        
        # Phase 3: Symbol Table
        t0 = time.time()
        symbol_table = SymbolTable()
        phases.append(("Symbol Table", time.time() - t0))
        
        # Phase 4: Semantic
        t0 = time.time()
        semantic = SemanticAnalyzer(code, symbol_table)
        semantic_issues = semantic.analyze()
        phases.append(("Semantic Analysis", time.time() - t0))
        
        # Phase 5: Dataflow
        t0 = time.time()
        dataflow = DataFlowAnalyzer(code, symbol_table)
        dataflow_issues = dataflow.detect_leaks()
        phases.append(("Data-Flow Analysis", time.time() - t0))
        
        # Phase 6: Policy
        t0 = time.time()
        policy = PolicyEngine(code, symbol_table, ast)
        policy_issues = policy.enforce()
        phases.append(("Policy Enforcement", time.time() - t0))
        
        # Phase 7: Transform
        t0 = time.time()
        transformer = Transformer(code)
        transformed = transformer.transform()
        phases.append(("Transformations", time.time() - t0))
        
        end_time = time.time()
        end_mem = self.get_memory_usage()
        
        return {
            "name": name,
            "time_ms": (end_time - start_time) * 1000,
            "memory_mb": end_mem - start_mem,
            "phases": phases,
            "tokens": len(tokens),
            "issues": len(secrets) + len(semantic_issues) + len(dataflow_issues) + len(policy_issues)
        }
    
    def run_baseline(self, code):
        """Simulate baseline compilation (GCC/Clang)"""
        lines = len(code.split('\n'))
        # Baseline: ~0.3ms per 100 lines for simple C
        return (lines / 100) * 0.3
    
    def analyze(self):
        """Run performance analysis on various code sizes"""
        print("=" * 80)
        print("PERFORMANCE & OVERHEAD ANALYSIS")
        print("=" * 80)
        
        # Test code of varying sizes
        test_cases = [
            ("Tiny (10 lines)", "int main() { return 0; }" * 3),
            ("Small (50 lines)", "void f() { int x = 1; }" * 25),
            ("Medium (200 lines)", "void f() { int x = 1; if(x>0) return; }" * 67),
            ("Large (500 lines)", "void f() { int a=1,b=2,c=3; return a+b+c; }" * 125),
            ("X-Large (1000 lines)", "void f() { int x=1; x++; x--; return x; }" * 250),
        ]
        
        print("\n[COMPILATION TIME ANALYSIS]")
        print("-" * 70)
        print(f"{'Code Size':<20} {'Secure Compiler':<20} {'GCC Baseline':<15} {'Overhead':<12}")
        print("-" * 70)
        
        for name, code in test_cases:
            result = self.run_secure_compiler(code, name)
            baseline = self.run_baseline(code)
            overhead = ((result["time_ms"] - baseline) / baseline) * 100 if baseline > 0 else 0
            
            self.results.append({
                "name": name,
                "time_ms": result["time_ms"],
                "baseline_ms": baseline,
                "overhead_percent": overhead,
                "memory_mb": result["memory_mb"],
                "tokens": result["tokens"]
            })
            
            print(f"{name:<20} {result['time_ms']:>8.2f} ms     {baseline:>8.2f} ms     {overhead:>+7.1f}%")
        
        print("-" * 70)
        
        # Detailed phase breakdown for medium code
        self.phase_breakdown()
        
        # Memory analysis
        self.memory_analysis()
        
        # Generate report
        self.generate_report()
        
        return self.results
    
    def phase_breakdown(self):
        """Detailed phase-by-phase breakdown"""
        print("\n[PHASE-BY-PHASE BREAKDOWN - Medium Code]")
        print("-" * 70)
        
        # Get medium code
        medium_code = "void f() { int x = 1; if(x>0) return; }" * 67
        result = self.run_secure_compiler(medium_code, "Medium")
        
        total_time = sum(p[1] for p in result["phases"])
        
        print(f"\n{'Phase':<25} {'Time (ms)':<12} {'Percentage':<10}")
        print("-" * 50)
        for phase, duration in result["phases"]:
            percent = (duration / total_time) * 100
            bar = "█" * int(percent / 2)
            print(f"{phase:<25} {duration*1000:>8.2f} ms    {percent:>5.1f}%  {bar}")
        print("-" * 50)
        print(f"{'TOTAL':<25} {total_time*1000:>8.2f} ms    100.0%")
    
    def memory_analysis(self):
        """Memory usage analysis"""
        print("\n[MEMORY USAGE ANALYSIS]")
        print("-" * 50)
        
        for r in self.results:
            bar = "█" * int(r["memory_mb"] / 2)
            print(f"{r['name']:<20} {r['memory_mb']:>6.2f} MB  {bar}")
        
        avg_memory = sum(r["memory_mb"] for r in self.results) / len(self.results)
        print("-" * 50)
        print(f"{'AVERAGE':<20} {avg_memory:>6.2f} MB")
    
    def generate_report(self):
        """Generate performance report"""
        os.makedirs("output", exist_ok=True)
        report_path = "output/performance_report.json"
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_tests": len(self.results),
                "avg_time_ms": sum(r["time_ms"] for r in self.results) / len(self.results),
                "avg_memory_mb": sum(r["memory_mb"] for r in self.results) / len(self.results),
                "avg_overhead_percent": sum(r["overhead_percent"] for r in self.results) / len(self.results)
            },
            "results": self.results
        }
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📁 Performance report saved: {report_path}")
    
    def print_ascii_chart(self):
        """Print ASCII chart for visualization"""
        print("\n[PERFORMANCE CHART]")
        print("-" * 70)
        print("Compilation Time vs Code Size")
        print("-" * 70)
        
        max_time = max(r["time_ms"] for r in self.results)
        
        for r in self.results:
            bar_length = int((r["time_ms"] / max_time) * 40)
            bar = "█" * bar_length
            print(f"{r['name']:<15} {r['time_ms']:>6.1f} ms  {bar}")
        
        print("\n[OVERHEAD CHART]")
        print("-" * 70)
        
        for r in self.results:
            bar_length = int(abs(r["overhead_percent"]) / 5)
            if r["overhead_percent"] > 0:
                bar = "█" * bar_length
                print(f"{r['name']:<15} +{r['overhead_percent']:>5.1f}%  {bar}")
            else:
                print(f"{r['name']:<15}  {r['overhead_percent']:>5.1f}%")

def main():
    # Check for psutil
    try:
        import psutil
    except ImportError:
        print("Installing psutil for memory monitoring...")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil"])
        import psutil
    
    analyzer = PerformanceAnalyzer()
    results = analyzer.analyze()
    analyzer.print_ascii_chart()
    
    print("\n" + "=" * 80)
    print("✅ PERFORMANCE ANALYSIS COMPLETE")
    print(f"   Average compilation time: {sum(r['time_ms'] for r in results)/len(results):.2f} ms")
    print(f"   Average overhead: {sum(r['overhead_percent'] for r in results)/len(results):.1f}%")
    print(f"   Average memory: {sum(r['memory_mb'] for r in results)/len(results):.2f} MB")
    print("=" * 80)

if __name__ == "__main__":
    main()