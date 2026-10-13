# Security Policy

## Supported Versions

This repository is demonstration code for a conference talk, not a library with
releases. Only the `main` branch is supported, and fixes land there.

| Version | Supported |
|---------|-----------|
| `main`  | ✅ Yes     |
| Older   | ❌ No      |

The code shows how to make cryptography replaceable. It is not meant to protect
real data as it stands: `LocalKms`, for example, keeps its keys in plain files.
A report that something here would be unsafe in production is still welcome,
especially if the demo teaches the wrong lesson.

## Reporting a Vulnerability

If you believe you've found a security vulnerability in this code, we strongly encourage you to contact us privately to allow time for remediation.

Please email us at **[oss-security@callibrity.com](mailto:oss-security@callibrity.com)** with the following details:

- A detailed description of the issue
- Steps to reproduce (if applicable)
- Any known workarounds
- Impact assessment (what's affected and how)
- Whether the vulnerability is publicly known

We aim to respond to all reports within **3 business days**, and to coordinate a fix within **7–14 business days**, depending on severity and complexity.

Please **do not** report vulnerabilities through public GitHub issues, pull requests, or discussions.

## Security Commitments

- We will publicly acknowledge and thank reporters (if desired).
- We will handle reports confidentially and professionally.
- We will publish advisories for confirmed vulnerabilities with CVSS scoring when applicable.
- We may fix the issue on `main` or advise on mitigation.

## Responsible Disclosure

We believe in responsible security research and disclosure. We do not currently run a bug bounty program, but we value all responsible disclosures and may credit you in security advisories if requested.

Thank you for helping keep this project and the community safe!
