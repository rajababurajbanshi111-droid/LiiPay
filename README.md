# LiPay 5.3 — Advanced Continuous Trust Payment Security System

LiPay 5.3 upgrades the existing LiPay 5.2 mobile/payment prototype into a single polished continuous-trust demonstration.

## Core flow

Payment Intent → Automatic Context → **Biometric / Identity Verification** → **OTP Verification** → **Pre-Payment Trust Check (prototype floor: 76/100)** → **MPIN** → Final Trust Re-check → Approve → Safe Receipt → History

The trust check is deliberately shown before final MPIN authorization.

## Demonstration scenarios

1. Normal low-risk payment
2. Medium-risk payment requiring step-up verification
3. High-risk payment blocked
4. Lost-phone / emergency recovery
5. Valid signed QR
6. Manipulated QR amount
7. Manipulated QR recipient
8. Expired QR
9. Replayed QR
10. Receipt sharing
11. Receipt saving
12. Payment history
13. Security Center
14. QR Integrity Lab

## Security / privacy behavior

- Country code selector is available in normal login, emergency recovery and account creation.
- Emergency recovery uses a separate emergency credential and enters visibly labelled Recovery Mode.
- Recovery protection can lock outgoing payments.
- Context signals are collected automatically; users do not choose their risk level.
- Trust score is explainable and uses the prototype thresholds:
  - 80–100: LOW RISK
  - 50–79: STEP-UP VERIFICATION
  - 0–49: HIGH RISK / BLOCK
- Face functionality is labelled **Face Presence Check — Demo** and is not represented as production biometric/liveness authentication.
- OTP and MPIN have no copy controls.
- MPIN, passwords, recovery credentials and other authentication secrets are not placed in receipts, history, sharing or QR payloads.
- Receipts contain safe transaction information only.
- Exact GPS coordinates are not stored in transaction history; location is represented by availability/status.
- Transaction binding covers transaction ID, recipient, amount, purpose and nonce.
- Final trust re-check detects binding changes, QR integrity problems, expiry and replay.
- Favorites never bypass security.
- Reverse-MPIN duress detection is included: entering the reverse of the configured MPIN activates the prototype emergency protection path.
- Optional **Second Signature** can be selected for a payment, requiring a second authorized approval before that exact transaction is released.
- For this prototype, trust displayed during the payment flow is kept strictly above 75 (minimum 76/100) as requested for demonstrations.

## Prototype disclosure

Credentials and demo data are stored locally for demonstration purposes. This is **not production banking security**. Production deployment requires secure backend authentication, encrypted sensitive data, server-side authorization, transaction signing, rate limiting, device binding, audit logging, HTTPS, and a server-side risk engine. A client-generated trust score must never be trusted as the sole financial authorization decision.

## Run

```bash
npm start
```

Then open `http://localhost:8000`.

The included service worker uses a LiPay 5.3 cache version so older cached application assets are invalidated.


## Second Signature Authorization

High-risk payments can now be automatically placed into `PENDING_SECOND_SIGNATURE`. The request is bound to the exact transaction (sender, recipient, amount, note, nonce, source and transaction ID), shows a transaction hash, requires independent second-approver MPIN plus second-device verification in this demo, supports approve/reject/timeout, and invalidates approval if the bound transaction data changes.

Demo second-approver MPIN: `1357`. This is prototype-only behavior; production deployments must use server-side authorization, real account roles, secure notification delivery, cryptographic signing, device attestation/liveness and audit storage.
