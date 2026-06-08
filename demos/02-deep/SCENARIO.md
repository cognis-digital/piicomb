# Demo 02 — deep: incident log triage

A security incident produced `incident_dump.log`, a noisy application log that
accidentally captured a wide spread of personally identifiable information.
Before the log can be shared with an external vendor it must be triaged and
redacted. This demo exercises the full PIICOMB 2.x recognizer set and the
presidio-style context-word boosting that separates real PII from decoys.

## What's in the log

Real PII (should be flagged):

- **EMAIL** `mei.lin@corp.example`
- **IPV4** `203.0.113.47`  (boosted by the word "client")
- **IPV6** `2001:0db8:85a3:0000:0000:8a2e:0370:7334`
- **MAC_ADDRESS** `3C:5A:B4:0F:1E:2D`  (boosted by "hwaddr")
- **CREDIT_CARD** `4111 1111 1111 1111` and Amex `378282246310005`  (Luhn-valid)
- **SSN** `536-42-7188`  (boosted by "SSN")
- **DOB** `03/14/1987`  (boosted by "DOB"; passes the calendar check)
- **US_PASSPORT** `X12345678`
- **ITIN** `912-78-3456`, **EIN** `12-3456789`
- **IBAN** `GB82 WEST 1234 5698 7654 32`  (mod-97 valid)
- **API_SECRET** `sk_live_EXAMPLE_9aZ2bX7qK`  (high entropy)
- **PHONE** `(415) 555-0142`, **INTL_PHONE** `+44 20 7946 0958`
- **US_ZIP** `94107-1234`

Decoys (should NOT be flagged):

- `999.1.2.3`            — octet > 255, fails the IPv4 validator
- `1234 5678 9012 3456`  — fails Luhn, not a credit card
- `000-12-3456`          — area 000, not a valid SSN
- `12345678` / `99887766` — bare serials with no PII context word

## Try it

```sh
# Full triage, table view
python -m piicomb scan demos/02-deep/incident_dump.log

# Machine-readable, CI-friendly (non-zero exit when PII is present)
python -m piicomb scan demos/02-deep/incident_dump.log --format json --fail-on-find

# Only network identifiers, no context boosting
python -m piicomb scan demos/02-deep/incident_dump.log --only IPV4,IPV6,MAC_ADDRESS --no-context

# Produce a shareable, redacted copy
python -m piicomb redact demos/02-deep/incident_dump.log > incident_dump.redacted.log

# Inspect the bundled recognizer set
python -m piicomb recognizers
```

The decoys above demonstrate why validators matter: without the Luhn / mod-97 /
SSN-issuance / calendar / entropy checks, every one of them would be a false
positive in a real triage.
