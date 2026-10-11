# Security Policy

## Reporting a vulnerability

If you find a security issue in Bankism, please email
**security@example.com** (replace this with your own address before publishing).
Include a description of the issue, the steps to reproduce it, and any relevant
details. Please do not open a public issue for security problems; reports will be
acknowledged as soon as possible.

## Security controls implemented

This repository is a prototype. The controls the code actually implements are:

- **Fail-closed classifier.** A missing `GEMINI_API_KEY`, an SDK exception, a
  timeout, an empty response, or invalid JSON all mark the classifier result as
  `failed`, which blocks the request instead of approving it
  (`guard/classifier.py`, `guard/merge.py`).
- **Deterministic rules are final.** Any match of rules R01-R06 blocks the
  request, and the classifier can only tighten a decision, never loosen one
  (`guard/rules.py`, `guard/merge.py`).
- **Input normalization against obfuscation.** Unicode NFKC folding, zero-width
  character stripping, base64/hex decoding, lowercasing, and leetspeak mapping
  run before rules and classification (`guard/normalize.py`).
- **Message length limit.** `POST /evaluate` rejects messages longer than 1000
  characters with HTTP 400 (`app.py`).
- **Rate limiting.** `POST /evaluate` allows at most 30 requests per minute per
  client IP and returns HTTP 429 beyond that (`app.py`).
- **Security headers on every response.** `Content-Security-Policy`,
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and
  `Referrer-Policy: strict-origin-when-cross-origin` (`app.py`).
- **No stack traces or secrets in responses.** Unexpected evaluation errors
  return a generic HTTP 500, and classifier errors record only the exception type
  name, never the API key (`app.py`, `guard/classifier.py`).
- **Message text is not retained.** The in-memory classifier cache is keyed by
  the SHA-256 hash of the normalised message, is capped at 256 entries, and never
  caches failed results (`guard/__init__.py`).
- **Untrusted-input handling.** The classifier system prompt instructs the model
  to treat the message as untrusted data and never follow instructions in it
  (`prompts/classifier.txt`).
- **Bounded external calls.** The classifier uses a 15-second HTTP timeout and at
  most one retry (`guard/classifier.py`).
- **No real banking API is called.** The approved-forwarding point is a labelled
  stub, so the prototype stays in a sandbox (`app.py`).

## Not implemented

This demonstration does **not** include user authentication, persistent storage,
encryption at rest, or a real core banking integration. The rate limit and
classifier cache live in memory and reset when the process restarts. Do not use
this code to handle real banking data without adding authentication and a
privacy review.
