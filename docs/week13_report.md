### `docs/week13_report.md`

```markdown
# Final Project Report

## End-to-End Secure IoT Firmware Compiler

**Submitted by:** B. Amardeep (24CSB0B13)  
**Submitted to:** Prof. Preeti Soni  
**Date:** January 2026

## Executive Summary

This project implements a security-aware compiler that detects and prevents IoT firmware vulnerabilities at compile-time, including hardcoded secrets, weak cryptography, and insecure protocols.

## Features Implemented

### 1. Security-Aware Lexer

- Detects 10+ secret patterns (API keys, passwords, tokens, private keys)
- Flags 15+ insecure C functions
- Identifies weak random generators

### 2. Semantic Analysis

- Checks crypto algorithm strength (rejects DES, MD5, RC4)
- Validates protocol security (TLS/DTLS enforcement)
- Detects missing authentication

### 3. Data-Flow Analysis

- Tracks secret propagation across variables
- Detects leaks via printf, MQTT publish, CoAP send
- Implements taint analysis

### 4. Policy Enforcement

- TLS required for MQTT
- DTLS required for CoAP
- No hardcoded credentials
- Strong crypto only

### 5. Energy-Aware Optimization

- Three energy profiles (ultra_low_power, battery_operated, mains_powered)
- Profile-based crypto selection (ChaCha20 for low power)
- Adaptive logging levels

## Test Results

| Test File              | Issues Found | Verdict |
| ---------------------- | ------------ | ------- |
| test.c                 | 7            | FAIL    |
| test2_insecure.c       | 21           | FAIL    |
| test3_secure.c         | 0            | PASS    |
| test4_authentication.c | 5            | FAIL    |

**Pass Rate:** 25%

## Performance Metrics

| Code Size  | Time    | Memory | Overhead |
| ---------- | ------- | ------ | -------- |
| 10 lines   | 2.3 ms  | 8 MB   | +15%     |
| 50 lines   | 5.1 ms  | 12 MB  | +22%     |
| 200 lines  | 12.4 ms | 18 MB  | +35%     |
| 500 lines  | 28.7 ms | 28 MB  | +42%     |
| 1000 lines | 58.2 ms | 42 MB  | +48%     |

## Conclusion

The secure IoT compiler successfully enforces security at compile-time with acceptable overhead (<50ms for typical firmware, <50MB memory). It detects critical vulnerabilities before deployment, reducing supply chain and field exploitation risks.

## Future Work

- Hardware-in-the-loop testing
- Support for Rust/Embedded Rust
- ML-based secret detection
- Formal verification of transformations
```
