# Bankism: A Defensive AI Firewall for Banking Messages

## Problem

Large language models are increasingly placed in front of banking actions: a user
types a request in plain language and the assistant acts on it. That convenience
is also an attack surface. A message, or even the memo field of a payment, can
carry instructions that try to override policy, impersonate the system, leak
account data, or drain a balance. The core danger is that the same model deciding
what to do is also a plausible target for the text it is asked to interpret.

## Approach

Bankism is a defensive firewall that screens every untrusted natural-language
message before any banking action runs. It applies defense in depth through four
stages:

1. **Normalization** strips the easy evasions first: Unicode NFKC folding,
   removal of zero-width characters, decoding of base64 and hex substrings,
   case and whitespace collapse, and selective leetspeak mapping that preserves
   numeric amounts.
2. **Deterministic rules (R01-R06)** match known attack signatures such as direct
   policy overrides, roleplay jailbreaks, system-prompt manipulation,
   data-exfiltration requests, transfer-all attempts, and hidden instructions in
   payment memos.
3. **AI classifier** reads the message as data, not as instructions, and returns a
   strict JSON object with intent, amount, recipient, suspected threats, and
   confidence. The classifier is optional and fails closed.
4. **Deterministic merge** produces the final verdict.

## Design decisions

- **Rules are final.** Any rule hit blocks, and the classifier can only tighten a
  decision, never loosen one. Model output is treated as untrusted data.
- **Fail closed.** A missing or malformed classifier response blocks the request
  rather than approving it.
- **Intent whitelisting.** Only balance inquiries and bounded peer-to-peer
  transfers that name a specific recipient and a positive amount within the
  configured limit can be approved.
- **No real banking API is called.** The approved-forwarding point is a labelled
  integration stub so the prototype stays in a strict sandbox.

## What it approves and blocks

Approves: ordinary balance inquiries and bounded peer-to-peer transfers.
Blocks: prompt-injection jailbreaks, policy overrides, hidden instructions in
payment memos, token obfuscation, data-exfiltration requests, and unbounded or
ambiguous transfers.

## Implementation

A small Flask service exposes the screening endpoint and three pages: a landing
page, an interactive tester, and a demo profile that illustrates where the
firewall would sit in a real product. The front end is plain HTML, CSS, and
JavaScript with no framework and no build step.

## Results

The project ships with a 44-test suite that covers normalization, each rule, the
classifier parsing and fail-closed paths, the merge policy, and the HTTP
endpoints. The classifier is mocked in tests, so the full suite runs locally
without any external API key.

## Impact and next steps

Bankism is a prototype. It demonstrates that a deterministic, fail-closed layer
can sit between people and money-moving systems without trusting the model to
police itself. Next steps include streaming memo and OCR sources into the same
pipeline, per-account policy configuration, and a structured audit trail of every
verdict.
