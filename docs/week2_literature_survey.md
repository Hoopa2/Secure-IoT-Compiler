# Week 2 Deliverable: Literature Survey & Gap Analysis

## Existing Tools

### Static Analysis Tools

| Tool                  | Strengths          | Weaknesses                 |
| --------------------- | ------------------ | -------------------------- |
| Clang Static Analyzer | Good bug detection | No IoT-specific rules      |
| Coverity              | Comprehensive      | Expensive, not IoT-focused |
| SonarQube             | Good UI            | Requires runtime           |

### Secure Compilers

| Compiler              | Security Features       | IoT Support       |
| --------------------- | ----------------------- | ----------------- |
| CompCert              | Formally verified       | No security rules |
| SMAC Compiler         | Side-channel protection | Research only     |
| GCC -fstack-protector | Buffer overflow         | Limited scope     |

## Research Gap

**No existing compiler provides:**

1. Combined secret detection + protocol security + energy optimization
2. Policy-driven compilation for IoT
3. Compile-time TLS/DTLS enforcement

## Our Contribution

- First end-to-end secure compiler for IoT
- Novel energy-security trade-off optimization
- Protocol-aware security rules
