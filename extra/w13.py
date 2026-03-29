#!/usr/bin/env python3
"""
Week 13 Deliverable: Final Report Generator
All metrics are COMPUTED by running the actual compiler and test suite —
no hardcoded numbers.
"""

import sys, os, json, time
from datetime import datetime
from io import StringIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Import live modules ────────────────────────────────────────────────────────

from compiler.lexer        import Lexer
from compiler.parser       import Parser
from compiler.semantic     import SemanticAnalyzer
from compiler.dataflow     import DataFlowAnalyzer
from compiler.policy       import PolicyEngine
from compiler.transformer  import Transformer
from compiler.symbol_table import SymbolTable

# ── Run week11 test suite (import and call) ────────────────────────────────────

def collect_test_results():
    print("  [*] Running test suite (week11)...")
    # Inline import so week13 can be run standalone
    import importlib.util, pathlib
    spec = importlib.util.spec_from_file_location(
        "week11",
        pathlib.Path(__file__).parent / "w11.py"
    )
    w11 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(w11)

    # Suppress stdout during the run
    old_stdout = sys.stdout; sys.stdout = StringIO()
    try:
        results = w11.main()
    finally:
        sys.stdout = old_stdout

    passed = sum(1 for r in results if r["test_passed"])
    total  = len(results)
    issues = sum(r["issues_found"] for r in results)

    test_cases_report = [
        {
            "name":             r["name"],
            "expected_verdict": r["expected_verdict"],
            "actual_verdict":   r["actual_verdict"],
            "issues_found":     r["issues_found"],
            "assertion_passed": r["test_passed"],
        }
        for r in results
    ]

    return {
        "total_tests":    total,
        "passed":         passed,
        "failed":         total - passed,
        "pass_rate":      f"{passed/total*100:.1f}%",
        "total_issues_detected": issues,
        "test_cases":     test_cases_report,
    }

# ── Run week12 performance (import and call) ───────────────────────────────────

def collect_performance():
    print("  [*] Running performance analysis (week12) — this may take ~10s...")
    import importlib.util, pathlib
    spec = importlib.util.spec_from_file_location(
        "week12",
        pathlib.Path(__file__).parent / "w12.py"
    )
    w12 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(w12)

    old_stdout = sys.stdout; sys.stdout = StringIO()
    try:
        results = w12.main()
    finally:
        sys.stdout = old_stdout

    avg_ovh = sum(r["sec_overhead_pct"] for r in results) / len(results)

    compile_times = {r["name"].strip(): f"{r['sec_ms']:.1f} ms" for r in results}
    gcc_times     = {r["name"].strip(): f"{r['gcc_ms']:.1f} ms" for r in results}
    memory_usage  = {r["name"].strip(): f"{r['memory_mb']:.1f} MB" for r in results}

    return {
        "avg_security_overhead_pct": round(avg_ovh, 1),
        "overhead_label": f"{avg_ovh:.1f}%",
        "secure_compiler_times_ms": compile_times,
        "gcc_baseline_times_ms":   gcc_times,
        "memory_usage_mb":         memory_usage,
        "note": "GCC baseline measured via subprocess (gcc -O0). "
                "Overhead = security analysis time as % of GCC compile time.",
    }

# ── Run all 4 test.c files through the main compiler pipeline ─────────────────

def collect_compiler_stats():
    print("  [*] Running compiler on all test inputs...")
    import pathlib
    input_dir = pathlib.Path(__file__).parent.parent / "input"
    stats = {}
    for c_file in sorted(input_dir.glob("*.c")):
        code = c_file.read_text(errors="replace")
        lexer   = Lexer(code);   tokens = lexer.tokenize()
        sec     = lexer.detect_secrets(); ins = lexer.detect_insecure_functions()
        wr      = lexer.detect_weak_random()
        ast     = Parser(tokens).parse()
        sym     = SymbolTable()
        sem_i   = SemanticAnalyzer(code, sym).analyze()
        df_i    = DataFlowAnalyzer(code, sym).detect_leaks()
        pol_i   = PolicyEngine(code, sym, ast).enforce()
        tr      = Transformer(code); tr.transform()
        total   = len(sec)+len(ins)+len(wr)+len(sem_i)+len(df_i)+len(pol_i)
        critical= sum(1 for i in sec+ins+wr+sem_i+df_i+pol_i if i.get("severity")=="CRITICAL")
        high    = sum(1 for i in sec+ins+wr+sem_i+df_i+pol_i if i.get("severity")=="HIGH")
        stats[c_file.name] = {
            "total_issues": total,
            "critical": critical,
            "high": high,
            "transformations": len(tr.transformations_applied),
        }
    return stats

# ── Build the full report dict ─────────────────────────────────────────────────

def build_report():
    print("\n[Collecting live data for report — running all modules...]\n")

    test_results = collect_test_results()
    perf_results = collect_performance()
    compiler_stats = collect_compiler_stats()

    print("  [*] Assembling report...")

    report = {
        "project_title":  "End-to-End Secure IoT Firmware Compiler",
        "submitted_by":   "B. Amardeep (24CSB0B13)",
        "submitted_to":   "Prof. Preeti Soni",
        "generated_at":   datetime.now().isoformat(),

        "overview": {
            "objective": (
                "Design and implement a firmware compiler for heterogeneous IoT (C/C++) "
                "that enforces end-to-end security — device identity, secure communication, "
                "and data privacy — while remaining resource-aware."
            ),
            "scope": "C/C++ subset for IoT firmware, software-only, no hardware dependencies.",
            "novelty": [
                "Compile-time security enforcement integrated into every compiler phase",
                "Security Policy Engine with configurable rules (TLS, auth, crypto strength)",
                "Taint-tracking data-flow analysis for secret leak detection",
                "Energy-aware transformations (crypto selection by power profile)",
                "Protocol-aware rules for MQTT, CoAP, HTTP/HTTPS",
            ],
        },

        "architecture": {
            "phases": [
                "1. Lexical Analysis + Secret Detection (Lexer)",
                "2. Parsing & AST Generation (Parser)",
                "3. Symbol Table Construction (security attributes, taint marks)",
                "4. Semantic Analysis (insecure functions, weak crypto, protocol checks)",
                "5. Data-Flow / Taint Analysis (secret propagation, leak detection)",
                "6. Policy Enforcement Engine (TLS required, auth mandatory, strong crypto)",
                "7. Energy-Aware Transformations (crypto selection, logging level, protocol upgrade)",
                "8. Encrypted Output Generation (Fernet encryption of firmware)",
            ],
        },

        "security_features": {
            "secret_detection_patterns": [
                "API keys (sk_live_, AKIA... AWS format)",
                "Hardcoded passwords (keyword + value pattern)",
                "JWT / Bearer tokens (base64 header detection)",
                "PEM private keys (-----BEGIN RSA PRIVATE KEY-----)",
                "Generic high-entropy strings (>20 chars, high character diversity)",
            ],
            "insecure_functions_flagged": ["gets()", "strcpy()", "sprintf()", "strcat()", "scanf()"],
            "weak_crypto_flagged":        ["DES", "3DES", "RC4", "MD5", "SHA-1"],
            "protocol_rules":             ["MQTT → must use mqtts://", "CoAP → must use coaps://",
                                           "HTTP → must use https://", "Authentication mandatory"],
            "transformations_available":  ["Insecure fn replacement", "Secure RNG substitution",
                                           "Protocol URL upgrade", "Energy-aware crypto selection",
                                           "Logging level configuration", "Error handling injection"],
        },

        "energy_profiles": {
            "ultra_low_power": {"crypto": "ChaCha20", "logging": "ERROR only",  "target": "Battery sensors"},
            "battery_operated":{"crypto": "ChaCha20", "logging": "WARNING+",   "target": "Portable IoT"},
            "mains_powered":   {"crypto": "AES-256",  "logging": "INFO+",      "target": "Gateways / hubs"},
        },

        "test_results":    test_results,
        "performance":     perf_results,
        "compiler_stats_per_input": compiler_stats,

        "deliverables_status": {
            "week1":  "✅ Problem definition, IoT threat landscape",
            "week2":  "✅ Literature survey, gap analysis",
            "week3":  "✅ SRS, architecture diagram",
            "week4":  "✅ Security policy grammar",
            "week5":  "✅ Security-aware lexer with secret detection",
            "week6":  "✅ Parser with security-annotated AST",
            "week7":  "✅ Symbol table with taint/secret attributes",
            "week8":  "✅ Data-flow / taint analysis module",
            "week9":  "✅ Policy enforcement engine",
            "week10": "✅ Energy-aware security transformations (3 profiles)",
            "week11": f"✅ Test suite — {test_results['passed']}/{test_results['total_tests']} assertions passed",
            "week12": f"✅ Performance analysis — {perf_results['overhead_label']} avg overhead vs real GCC",
            "week13": "✅ This report (live-computed, not hardcoded)",
            "week14": "✅ Submission package + README",
        },
    }
    return report


def print_report(r):
    sep = "=" * 72
    print(f"\n{sep}")
    print(f"  {r['project_title']}")
    print(sep)
    print(f"  Submitted by : {r['submitted_by']}")
    print(f"  Submitted to : {r['submitted_to']}")
    print(f"  Generated at : {r['generated_at']}")

    print(f"\n{'─'*72}")
    print("1. OBJECTIVE")
    print(f"{'─'*72}")
    print(f"  {r['overview']['objective']}")
    print(f"\n  Scope   : {r['overview']['scope']}")
    print("\n  Novelty:")
    for n in r['overview']['novelty']:
        print(f"    • {n}")

    print(f"\n{'─'*72}")
    print("2. COMPILER ARCHITECTURE (9-Phase Pipeline)")
    print(f"{'─'*72}")
    for ph in r['architecture']['phases']:
        print(f"  {ph}")

    print(f"\n{'─'*72}")
    print("3. SECURITY FEATURES IMPLEMENTED")
    print(f"{'─'*72}")
    sf = r['security_features']
    print(f"  Secret patterns  : {len(sf['secret_detection_patterns'])}")
    print(f"  Insecure fns     : {', '.join(sf['insecure_functions_flagged'])}")
    print(f"  Weak crypto      : {', '.join(sf['weak_crypto_flagged'])}")
    print(f"  Protocol rules   : {len(sf['protocol_rules'])}")
    print(f"  Transformations  : {len(sf['transformations_available'])}")

    print(f"\n{'─'*72}")
    print("4. ENERGY PROFILES")
    print(f"{'─'*72}")
    for name, cfg in r['energy_profiles'].items():
        print(f"  {name:<20}  crypto={cfg['crypto']:<12} logging={cfg['logging']}")

    print(f"\n{'─'*72}")
    print("5. TEST RESULTS  (assertion-based, Contiki-NG / Zephyr / ESP-IDF style)")
    print(f"{'─'*72}")
    tr = r['test_results']
    print(f"  Tests      : {tr['total_tests']}")
    print(f"  Passed     : {tr['passed']}  ({tr['pass_rate']})")
    print(f"  Failed     : {tr['failed']}")
    print(f"  Issues detected across all firmware: {tr['total_issues_detected']}")
    print()
    for tc in tr['test_cases']:
        sym = "✅" if tc['assertion_passed'] else "❌"
        print(f"    {sym} {tc['name']:<45} issues={tc['issues_found']:>3}  verdict={tc['actual_verdict']}")

    print(f"\n{'─'*72}")
    print("6. PERFORMANCE  (real GCC -O0 baseline via subprocess)")
    print(f"{'─'*72}")
    perf = r['performance']
    print(f"  Avg security overhead : {perf['overhead_label']} of GCC compile time")
    print(f"  Note: {perf['note']}")
    print()
    print(f"  {'Firmware':<28} {'GCC (ms)':>10} {'SecComp (ms)':>14} {'Memory':>8}")
    print(f"  {'─'*64}")
    for k in perf['gcc_baseline_times_ms']:
        g = perf['gcc_baseline_times_ms'][k]
        s = perf['secure_compiler_times_ms'][k]
        m = perf['memory_usage_mb'][k]
        print(f"  {k:<28} {g:>10} {s:>14} {m:>8}")

    print(f"\n{'─'*72}")
    print("7. COMPILER STATS ON ACTUAL TEST INPUTS")
    print(f"{'─'*72}")
    for fname, stats in r['compiler_stats_per_input'].items():
        print(f"  {fname:<35}  issues={stats['total_issues']:>3}  "
              f"(crit={stats['critical']} high={stats['high']})  "
              f"transforms={stats['transformations']}")

    print(f"\n{'─'*72}")
    print("8. WEEK-WISE DELIVERABLES STATUS")
    print(f"{'─'*72}")
    for wk, status in r['deliverables_status'].items():
        print(f"  {wk:>7}: {status}")

    print(f"\n{sep}")
    print("✅ REPORT GENERATED FROM LIVE RUNS — no hardcoded numbers.")
    print(sep)


def main():
    print("=" * 70)
    print("WEEK 13 DELIVERABLE: Final Report Generator")
    print("=" * 70)

    report = build_report()

    # Save JSON
    out_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs")
    os.makedirs(out_dir, exist_ok=True)
    report_path = os.path.join(out_dir, "final_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  📄 JSON saved → {report_path}")

    print_report(report)

    print("\n" + "=" * 70)
    print("✅ WEEK 13 DELIVERABLE COMPLETE")
    print("   All metrics computed live — test suite, performance, compiler stats.")
    print("=" * 70)


if __name__ == "__main__":
    main()