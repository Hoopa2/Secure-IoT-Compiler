# Week 3 Deliverable: Software Requirements Specification

## Functional Requirements

### FR1: Lexical Security Analysis

- Detect hardcoded secrets (API keys, passwords, tokens)
- Flag insecure C functions (gets, strcpy, sprintf)
- Identify weak random generators

### FR2: Semantic Security Analysis

- Check crypto algorithm strength
- Validate protocol security (TLS/DTLS)
- Ensure proper authentication

### FR3: Data-Flow Analysis

- Track secret propagation
- Detect sensitive data leaks via printf/send
- Taint analysis across assignments

### FR4: Policy Enforcement

- TLS required for MQTT
- DTLS required for CoAP
- No hardcoded credentials
- Strong crypto only

### FR5: Energy-Aware Optimization

- Profile-based crypto selection
- Adaptive logging levels
- Resource-aware transformations

## Non-Functional Requirements

| Requirement         | Target                 |
| ------------------- | ---------------------- |
| Compilation time    | < 100ms per 1000 lines |
| Memory overhead     | < 50MB                 |
| Detection accuracy  | > 90%                  |
| False positive rate | < 10%                  |

## Architecture
