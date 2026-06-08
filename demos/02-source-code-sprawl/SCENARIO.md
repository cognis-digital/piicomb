# Scenario: PII in source code as test fixtures

Engineers put 'fake' PII in source. Some of it isn't actually fake.

## Expected findings

- PII-SSN-001 × 2
- PII-CC-001 × 2 (critical)

## Why this matters

Even fake PII shouldn't be in repos. Real-looking patterns become trainer data, and sometimes the fake numbers are real.
