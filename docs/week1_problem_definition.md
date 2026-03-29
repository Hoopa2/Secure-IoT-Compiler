# Week 1 Deliverable: Problem Definition & Context

## Project Title

End-to-End Secure IoT Firmware Compiler

## Problem Statement

IoT devices are increasingly targeted by attackers due to:

- Hardcoded credentials in firmware
- Weak cryptographic implementations
- Insecure communication protocols (MQTT without TLS, CoAP without DTLS)
- Buffer overflow vulnerabilities
- Lack of proper authentication

## Current Challenges

1. **Compile-time security gaps** - Traditional compilers focus on correctness, not security
2. **Resource constraints** - IoT devices have limited memory, CPU, and battery
3. **Supply chain risks** - Insecure code propagates through firmware supply chain

## Proposed Solution

A security-aware compiler that:

- Detects vulnerabilities at compile-time
- Enforces security policies automatically
- Optimizes for energy constraints
- Generates secure firmware by default

## Threat Landscape

| Threat                | Impact          | Mitigation              |
| --------------------- | --------------- | ----------------------- |
| Hardcoded credentials | Device takeover | Static secret detection |
| Weak crypto           | Data decryption | Crypto strength checks  |
| No TLS/DTLS           | Eavesdropping   | Protocol enforcement    |
| Buffer overflow       | RCE             | Function replacement    |

## Scope

- Language: C/C++ subset for IoT
- Target: Embedded devices (ESP32, ARM Cortex-M, etc.)
- Security: Compile-time enforcement only
