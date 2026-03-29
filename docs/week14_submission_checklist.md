# Week 14 Deliverable: Final Submission Checklist

## Submission Package Contents

### Source Code

- [x] `main.py` - Main compiler driver
- [x] `config.py` - Security policies configuration
- [x] `requirements.txt` - Dependencies
- [x] `compiler/` - All compiler modules (8 files)

### Test Firmware

- [x] `input/test.c` - Basic test
- [x] `input/test2_insecure.c` - Complex insecure firmware
- [x] `input/test3_secure.c` - Secure firmware (passes all checks)
- [x] `input/test4_authentication.c` - Authentication tests

### Test Suite

- [x] `tests/test_suite.py` - Complete test runner

### Performance Analysis

- [x] `performance/performance_analysis.py` - Overhead measurement

### Documentation

- [x] `docs/week1_problem_definition.md`
- [x] `docs/week2_literature_survey.md`
- [x] `docs/week3_srs.md`
- [x] `docs/week4_policy_grammar.md`
- [x] `docs/week13_report.md`
- [x] `docs/week14_submission_checklist.md`

### Week-wise Deliverables

- [x] `deliverables/week5_lexer_demo.py`
- [x] `deliverables/week6_parser_demo.py`
- [x] `deliverables/week7_symbol_table_demo.py`
- [x] `deliverables/week8_dataflow_demo.py`
- [x] `deliverables/week9_policy_demo.py`
- [x] `deliverables/week10_transformer_demo.py`
- [x] `deliverables/week11_test_suite.py`
- [x] `deliverables/week12_performance.py`
- [x] `deliverables/week13_report_generator.py`

## Verification Steps

### 1. Install Dependencies

```bash
pip install -r requirements.txt
pip install psutil  # for performance analysis
```
