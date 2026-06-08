# Scenario: PII in production logs

Logs contain SSN + CC + email + phone — common when sanitization is partial.

## Expected findings

- PII-SSN-001
- PII-CC-001 (critical)
- PII-EMAIL-001
- PII-PHONE-001

## Why this matters

Logs are often the largest PII exposure surface. Run PIICOMB pre-shipping log files.
