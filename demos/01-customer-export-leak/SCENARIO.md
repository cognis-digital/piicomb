# Scenario: Customer-list CSV in dev/share folder

An engineer accidentally exported customer data to a shared folder.

## Expected findings

- PII-SSN-001 × 3 (critical)
- PII-EMAIL-001 × 3
- PII-PHONE-001 × 3
- PII-DOB-001 × 3
- PII-PASS-001 × 2

## Why this matters

Common GDPR/CCPA breach pattern. PIICOMB scans dev folders to surface these BEFORE they leave the network.
