# Third-Party Notices

Praxis vendors the following data assets. Each retains its original license
and attribution as required.

## MITRE ATLAS knowledge base

- **File:** `cli/data/atlas-knowledge.json` (technique/tactic/mitigation/case-study enrichment)
- **Source:** MITRE ATLAS — https://atlas.mitre.org/ (snapshot 2026-04, `atlas-nodes-04-2026.csv`)
- **Copyright:** Copyright 2026 The MITRE Corporation. Approved for Public Release; Distribution Unlimited.
- **License:** Apache License 2.0 — see https://www.apache.org/licenses/LICENSE-2.0
- ATLAS is a trademark of The MITRE Corporation. Use of the data does not imply MITRE endorsement.

## Endpoint AI Agent Abuse (EAA) catalog

- **File:** `cli/data/eaa-catalog.json` (technique catalog backing EndpointAgentAbuseAgent)
- **Source:** https://github.com/0x4D31/endpoint-ai-agent-abuse (v0.1.0)
- **License:** CC0-1.0 (public domain dedication) — https://creativecommons.org/publicdomain/zero/1.0/

## Documented non-working credential examples

- **File:** `cli/data/documented-secret-examples.json`
- **Source:** [AWS S3 authentication examples](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/RESTAuthentication.html)
- Contains one exact identifier AWS labels non-working, with our own annotations.
  No documentation prose is reproduced. This is factual example provenance, not
  permission to suppress arbitrary credentials, test files, or repository history.

## Standards referenced (not vendored)

Findings are mapped to the following frameworks; their text is not reproduced:
OWASP Top 10 for LLM Applications · OWASP Machine Learning Security Top 10 ·
OWASP Top 10 for Agentic Applications · MITRE ATLAS · NIST AI 600-1 ·
NIST AI RMF · AVID · EU AI Act (Regulation (EU) 2024/1689) · ISO/IEC 42001 ·
Google Secure AI Framework.
