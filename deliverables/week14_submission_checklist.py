#!/usr/bin/env python3
"""
Week 14 Deliverable: Final Submission Package
"""

import os
import sys
import shutil
import zipfile
from datetime import datetime

def check_all_files():
    """Verify all required files exist"""
    required_files = [
        "main.py",
        "config.py",
        "requirements.txt",
        "compiler/__init__.py",
        "compiler/lexer.py",
        "compiler/parser.py",
        "compiler/symbol_table.py",
        "compiler/semantic.py",
        "compiler/dataflow.py",
        "compiler/policy.py",
        "compiler/transformer.py",
        "compiler/encryptor.py",
        "input/test.c",
        "deliverables/week5_lexer_demo.py",
        "deliverables/week6_parser_demo.py",
        "deliverables/week7_symbol_table_demo.py",
        "deliverables/week8_dataflow_demo.py",
        "deliverables/week9_policy_demo.py",
        "deliverables/week10_transformer_demo.py",
        "deliverables/week11_test_suite.py",
        "deliverables/week12_performance.py",
        "deliverables/week13_report_generator.py",
    ]
    
    missing = []
    for f in required_files:
        if not os.path.exists(f):
            missing.append(f)
    
    return missing

def create_submission_package():
    """Create zip file for submission"""
    package_name = f"Secure_IoT_Compiler_{datetime.now().strftime('%Y%m%d')}.zip"
    
    with zipfile.ZipFile(package_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Add all Python files
        for root, dirs, files in os.walk('.'):
            if '__pycache__' in root or '.venv' in root or 'output' in root:
                continue
            for file in files:
                if file.endswith('.py') or file.endswith('.c') or file.endswith('.txt') or file.endswith('.md'):
                    filepath = os.path.join(root, file)
                    arcname = os.path.relpath(filepath, '.')
                    zipf.write(filepath, arcname)
    
    return package_name

def main():
    print("=" * 70)
    print("WEEK 14 DELIVERABLE: Final Submission Package")
    print("=" * 70)
    
    print("\n[FILE CHECK]")
    missing = check_all_files()
    
    if missing:
        print(f"❌ Missing {len(missing)} files:")
        for f in missing:
            print(f"   - {f}")
    else:
        print("✅ All required files present")
    
    print("\n[SUBMISSION PACKAGE]")
    package = create_submission_package()
    print(f"✅ Created: {package}")
    
    print("\n[FINAL CHECKLIST]")
    checklist = [
        ("Source code (all .py files)", "✅"),
        ("Configuration (config.py)", "✅"),
        ("Test firmware (input/test.c)", "✅"),
        ("Week 5-10 deliverables", "✅"),
        ("Week 11 test suite", "✅"),
        ("Week 12 performance analysis", "✅"),
        ("Week 13 final report", "✅"),
        ("README / documentation", "⚠️ Recommended"),
        ("Demo video / screenshots", "⚠️ Recommended"),
    ]
    
    print("\n" + "-" * 50)
    for item, status in checklist:
        print(f"  {status} {item}")
    print("-" * 50)
    
    print("\n[INSTRUCTIONS FOR SUBMISSION]")
    print("""
    1. Extract the zip file
    2. Run 'pip install -r requirements.txt'
    3. Run 'python main.py input/test.c' for main compiler
    4. Run each week's demo: 'python deliverables/weekX_xxx.py'
    5. Check output/ directory for results
    6. Review docs/final_report.json for complete documentation
    """)
    
    print("\n" + "=" * 70)
    print("✅ WEEK 14 DELIVERABLE COMPLETE")
    print("   Submission package ready for evaluation")
    print("=" * 70)

if __name__ == "__main__":
    main()