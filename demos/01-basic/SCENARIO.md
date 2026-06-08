# Demo 01 — Combing a customer export for PII before sharing

You are about to hand `customer_export.csv` to a third-party analytics
vendor. Before it leaves your laptop, you want to know exactly what
personally identifiable information it contains — and you want to ship a
masked copy instead of the raw one.

## The input

`customer_export.csv` is a small, realistic CRM dump with a mix of:

- **Real PII** — valid emails, US phone numbers, SSNs that pass the
  SSA area/group rules, credit cards that pass the Luhn checksum
  (Visa `4111…`, Mastercard `5500…`, Amex `378…`), dates of birth, a
  US passport number, and a driver-license number.
- **Deliberate decoys** that should NOT be flagged:
  - `000-12-3456` — invalid SSN (area `000`).
  - `1234 5678 9012 3456` — 16 digits but fails Luhn → not a card.
  - `02/30/1991` — implausible date (Feb 30) → not a DOB.
  - Row `1004` — no PII at all.

This is what makes the demo useful: it proves PIICOMB validates, not just
pattern-matches.

## Run it

Discover everything, human-readable:

```
python -m piicomb scan demos/01-basic/customer_export.csv
```

Machine-readable (for piping into a ticket or dashboard):

```
python -m piicomb scan demos/01-basic/customer_export.csv --format json
```

Use it as a CI gate — non-zero exit if any PII slips into a commit:

```
python -m piicomb scan demos/01-basic/customer_export.csv --fail-on-find
```

Produce a shareable, masked copy:

```
python -m piicomb redact demos/01-basic/customer_export.csv > safe_export.csv
```

## What you should see

The `scan` reports the valid emails, phones, SSNs, cards, DOBs, passport,
and DL — each with a confidence score and a masked context snippet — while
silently dropping the three decoys above. `redact` emits the same file with
every detected value replaced by `[REDACTED-…1234]` (last 4 kept for
reconciliation).
