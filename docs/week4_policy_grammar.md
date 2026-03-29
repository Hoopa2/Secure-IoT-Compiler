# Week 4 Deliverable: Security Policy Grammar

## Policy Definition Language (DSL)

```ebnf
PolicyFile     = { PolicyRule }
PolicyRule     = RuleName ":" Condition [ "->" Action ]
RuleName       = identifier
Condition      = "HARDCODED_SECRET" | "WEAK_RANDOM" | "NO_TLS" | "WEAK_CRYPTO"
Action         = "ERROR" | "WARN" | "FIX" | "IGNORE"
```
