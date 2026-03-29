# End-to-End Secure IoT Firmware Compiler

> **B. Amardeep | 24CSB0B13 | CSE-B**  
> Compiler Design Project | Prof. Preeti Soni

A security-aware compiler for C/C++ IoT firmware that enforces end-to-end security **at compile time** — detecting and fixing vulnerabilities before firmware is ever deployed to a device.

---

## What It Does

Traditional compilers like GCC and Clang care about correctness and performance — not security. IoT firmware routinely ships with hardcoded passwords, weak encryption, and insecure protocols, making billions of devices vulnerable.

This compiler runs a **9-phase pipeline** on top of normal compilation that:

- Detects hardcoded secrets, weak crypto, and insecure functions
- Tracks how secret data flows through your program (taint analysis)
- Enforces security policies (TLS required, no weak RNG, etc.)
- Automatically transforms insecure code into secure equivalents
- Selects energy-efficient crypto based on the device's power profile
- Outputs encrypted firmware ready for secure distribution

Average overhead vs plain GCC: **~7%**. Peak memory: **<2 MB**.

---

## Project Structure

```
secure-iot-compiler/
├── main.py                          # Entry point — runs the full 9-phase pipeline
├── config.py                        # Security policies, crypto rules, energy profiles
├── requirements.txt                 # Python dependencies
│
├── compiler/
│   ├── lexer.py                     # Tokeniser + secret/RNG/insecure-function detection
│   ├── parser.py                    # Builds security-annotated AST
│   ├── symbol_table.py              # Scoped symbol table with taint/secret tracking
│   ├── semantic.py                  # Weak crypto, protocol, error-handling checks
│   ├── dataflow.py                  # Taint propagation + secret leak detection
│   ├── policy.py                    # TLS/DTLS/auth policy enforcement engine
│   ├── transformer.py               # Applies security + energy-aware code fixes
│   └── encryptor.py                 # Fernet-encrypts the output firmware
│
├── input/                           # Test firmware files
│   ├── test.c                       # Basic violations (9 issues)
│   ├── test2_insecure.c             # Heavy violations — 41 issues, 17 critical
│   └── test3_secure.c               # Clean secure firmware (should PASS with 0 issues)
│
├── tests/
│   └── test_suite.py                # Assertion-based test suite (8/8 passing)
│
├── deliverables/                    # Weekly demo scripts
│   ├── week5_lexer_demo.py
│   ├── week6_parser_demo.py
│   ├── week7_symbol_table_demo.py
│   ├── week8_dataflow_demo.py
│   ├── week9_policy_demo.py
│   ├── week10_transformer_demo.py
│   ├── week11_test_suite.py         # Full test suite
│   ├── week12_performance.py        # Real GCC baseline benchmarks
│   └── week13_report_generator.py   # Generates final live report
│
├── performance/
│   └── performance_analysis.py      # Standalone performance benchmarking
│
├── docs/
│   ├── week1_problem_definition.md
│   ├── week2_literature_survey.md
│   ├── week3_srs.md
│   ├── week4_policy_grammar.md
│   ├── week13_report.md
│   └── final_report.json
│
└── output/                          # Generated on each run
    ├── secure_firmware.enc          # Fernet-encrypted firmware
    ├── transformed_firmware.c       # Patched source code
    └── security_report.json         # Full issue + transformation report
```

---

## Requirements

- Python 3.8+
- GCC (required for the performance benchmark in `week12_performance.py`)

Install Python dependencies:

```bash
pip install -r requirements.txt
```

`requirements.txt` contains:

```
cryptography>=41.0.0
```

---

## Quick Start

### Basic usage

```bash
python main.py input/test.c
```

### Verbose output (shows token count, AST nodes, symbol table)

```bash
python main.py input/test.c -v
```

### Choose an energy profile

```bash
# Coin-cell sensors — uses ChaCha20, ERROR-only logging
python main.py input/test.c --energy-profile ultra_low_power

# Portable IoT devices (default) — uses ChaCha20, WARNING+ logging
python main.py input/test.c --energy-profile battery_operated

# Gateways and hubs — uses AES-256, INFO+ logging
python main.py input/test.c --energy-profile mains_powered
```

### Custom output directory

```bash
python main.py input/test2_insecure.c -o my_output/
```

### Skip report generation

```bash
python main.py input/test.c --no-report
```

---

## Running the Test Suite

```bash
python tests/test_suite.py
```

Or using the deliverables version:

```bash
python deliverables/week11_test_suite.py
```

Expected result: **8/8 assertions passed (100% accuracy)**

---

## Running the Performance Benchmark

Requires GCC to be installed and accessible on your PATH.

```bash
python deliverables/week12_performance.py
```

This compiles each test file with plain `gcc -O0` as a baseline, then runs the security analysis on top and reports the overhead percentage.

---

## Generating the Final Report

```bash
python deliverables/week13_report_generator.py
```

Produces a live-computed report in `docs/final_report.json` with actual metrics from your machine.

---

## The 9-Phase Pipeline

When you run `main.py`, the compiler executes these phases in order:

| Phase                  | What Happens                                                          |
| ---------------------- | --------------------------------------------------------------------- |
| 1 — Read Source        | Loads the `.c` file into memory                                       |
| 2 — Lexical Analysis   | Tokenises the code; detects secrets, insecure functions, weak RNGs    |
| 3 — Parsing            | Builds a security-annotated Abstract Syntax Tree (AST)                |
| 4 — Symbol Table       | Tracks all variables with taint and secret attributes                 |
| 5 — Semantic Analysis  | Checks for weak crypto, insecure protocols, missing error handling    |
| 6 — Data-Flow Analysis | Tracks how secret values propagate; flags leaks via `printf` etc.     |
| 7 — Policy Enforcement | Enforces TLS/DTLS requirements, auth policy, strong-crypto-only rules |
| 8 — Transformations    | Rewrites insecure code; applies energy-profile crypto selection       |
| 9 — Encryption         | Fernet-encrypts the transformed firmware for secure distribution      |

---

## What Gets Detected

### Hardcoded Secrets

- API keys, passwords, JWT tokens, private keys, AWS credentials
- Pattern: `api_key = "sk_live_..."` or `password = "hunter2"`

### Insecure C Functions

- `gets()`, `strcpy()`, `strcat()`, `sprintf()`, `scanf()`, `sscanf()`, `memcpy()`

### Weak Random Number Generators

- `rand()`, `random()`, `srand()`, `rand_r()`
- Safe alternatives (`esp_random`, `getrandom`, `RAND_bytes`) are whitelisted and never flagged

### Weak Cryptography

- Ciphers: DES, 3DES, RC4, Blowfish
- Hashes: MD5, SHA-1

### Insecure Protocols

- `mqtt://` — requires `mqtts://` (MQTT over TLS)
- `coap://` — requires `coaps://` (CoAP over DTLS)
- `http://` — requires `https://`

### Missing Authentication

- `mqtt_connect()` calls without username, password, or certificate
- `coap_send()` / `coap_connect()` calls without PSK or certificate

### Secret Data Leaks

- Variables containing secrets that are passed to `printf`, `fprintf`, `mqtt_publish`, `coap_send`

---

## What Gets Auto-Fixed (Transformations)

The transformer in Phase 8 rewrites your code automatically:

| Insecure                          | Secure Replacement                       |
| --------------------------------- | ---------------------------------------- |
| `gets(buf)`                       | `fgets(buf, sizeof(buf), stdin)`         |
| `strcpy(d, s)`                    | `strncpy(d, s, sizeof(d)-1)`             |
| `sprintf(...)`                    | `snprintf(..., sizeof(buf), ...)`        |
| `strcat(d, s)`                    | `strncat(d, s, sizeof(d)-1)`             |
| `rand()`                          | `SECURE_RANDOM()` macro (platform-aware) |
| `mqtt://`                         | `mqtts://`                               |
| `coap://`                         | `coaps://`                               |
| `http://`                         | `https://`                               |
| `AES-256-CBC` (low-power profile) | `ChaCha20`                               |
| `RSA-2048` (low-power profile)    | `ECC-256`                                |

---

## Energy Profiles

Pick a profile matching your hardware with `--energy-profile`:

| Profile            | Crypto   | Logging    | Designed For           |
| ------------------ | -------- | ---------- | ---------------------- |
| `ultra_low_power`  | ChaCha20 | ERROR only | Coin-cell sensors      |
| `battery_operated` | ChaCha20 | WARNING+   | Portable IoT (default) |
| `mains_powered`    | AES-256  | INFO+      | Gateways and hubs      |

**Why ChaCha20 for low-power?** On Cortex-M0/M0+ MCUs without hardware AES acceleration, ChaCha20 uses ~40% fewer operations per byte than AES-256-CBC, directly extending battery life.

---

## Security Policies (config.py)

All policies are toggled in `config.py`:

```python
SECURITY_POLICIES = {
    "NO_HARDCODED_KEYS":        True,   # Block hardcoded crypto keys
    "TLS_REQUIRED":             True,   # MQTT/HTTP must use TLS
    "NO_WEAK_RANDOM":           True,   # Block rand(), random()
    "NO_INSECURE_FUNCTIONS":    True,   # Block gets(), strcpy(), etc.
    "NO_HARDCODED_CREDENTIALS": True,   # Block passwords in source
    "DTLS_REQUIRED_FOR_COAP":   True,   # CoAP must use DTLS
    "STRONG_CRYPTO_ONLY":       True,   # Block DES, MD5, RC4, etc.
    "MUTUAL_AUTH_REQUIRED":     False,  # Optional: enforce mTLS
}
```

Set any value to `False` to disable that policy check.

---

## Output Files

Every run produces three files in the output directory:

| File                     | Description                                               |
| ------------------------ | --------------------------------------------------------- |
| `transformed_firmware.c` | Your code with all security patches applied               |
| `secure_firmware.enc`    | Fernet-encrypted version of the transformed code          |
| `security_report.json`   | Full JSON report: all issues, severities, transformations |

To use a consistent encryption key across runs (so you can decrypt later), set the environment variable:

```bash
export IOT_COMPILER_KEY="your-fernet-key-here"
python main.py input/test.c
```

If no key is set, a fresh key is generated each run (the `.enc` file won't be decryptable across runs without it).

---

## Test Results Summary

| File               | Issues | Critical | High | Transforms | Verdict                  |
| ------------------ | ------ | -------- | ---- | ---------- | ------------------------ |
| `test.c`           | 9      | 4        | 4    | 5          | FAIL (expected)          |
| `test2_insecure.c` | 41     | 17       | 17   | 8          | FAIL (expected)          |
| `test3_secure.c`   | 1      | 0        | 0    | 4          | PASS (0 false positives) |

---

## Performance

Measured against a real `gcc -O0` baseline:

| Firmware Size | GCC (ms) | Security Analysis (ms) | Overhead  |
| ------------- | -------- | ---------------------- | --------- |
| ~18 lines     | 185      | 6                      | +3.2%     |
| ~130 lines    | 194      | 9                      | +4.6%     |
| ~125 lines    | 198      | 14                     | +7.1%     |
| ~505 lines    | 253      | 35                     | +13.8%    |
| **Average**   |          |                        | **+7.2%** |

Peak memory usage across all test files: **< 2 MB**

---

## Supported Platforms (Software Only)

The compiler targets these platforms in its output and analysis — no actual hardware is required to run it:

- ESP32 (ESP-IDF)
- ARM Cortex-M (Zephyr RTOS)
- Contiki-NG
- Bare-metal embedded C

---

## Known Limitations

1. The parser handles a C subset — complex macros, multi-file projects, and `#ifdef` chains are not fully supported.
2. Policy checks use line-level pattern matching, not full AST traversal, which can miss some edge cases.
3. The MQTT authentication check may miss scenarios where `mqtt_connect` and `mqtt_connect_auth` appear on the same line.
4. The GCC baseline measurement includes ~180ms process startup overhead, which slightly understates the real relative cost on large projects.

---

## Future Work

- Replace the custom parser with `pycparser` or Clang AST bindings for full C support
- AST-driven policy engine (traverse the tree rather than scanning raw text)
- Rust / Embedded Rust support
- Hardware-in-the-loop testing on real ESP32 and Nordic nRF52 boards
- ML-based secret detection to reduce false positives further
- Formal verification of security transformations using Coq or Isabelle
- VS Code extension for inline security warnings as you type

---

## References

1. Leroy, X. (2009). _Formal verification of a realistic compiler_. CACM 52(7).
2. Wurm et al. (2016). _Security analysis on consumer and industrial IoT devices_. ASP-DAC.
3. Alrawi et al. (2019). _SoK: Security evaluation of home-based IoT deployments_. IEEE S&P.
4. Schwartz et al. (2010). _All you ever wanted to know about dynamic taint analysis_. IEEE S&P.
5. Bernstein, D.J. (2008). _ChaCha, a variant of Salsa20_. SASC Workshop.
6. OWASP Foundation (2023). _OWASP IoT Top 10_. https://owasp.org/www-project-internet-of-things
