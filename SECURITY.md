# Security Policy

WebAuthn.Net implements an authentication mechanism, so its security is taken seriously. This document describes which versions receive security fixes and how to report a vulnerability responsibly.

## Supported Versions

Security fixes are released only for the version lines listed below. Fixes are shipped as new releases of a supported line. Older lines no longer receive updates, and users of those versions are strongly encouraged to upgrade.

| Version | Supported |
| ------- | --------- |
| 3.x     | ✅        |
| < 3.0   | ❌        |

This policy applies to every package published from this repository:

- [WebAuthn.Net](https://www.nuget.org/packages/WebAuthn.Net/)
- [WebAuthn.Net.Storage.SqlServer](https://www.nuget.org/packages/WebAuthn.Net.Storage.SqlServer/)
- [WebAuthn.Net.Storage.PostgreSql](https://www.nuget.org/packages/WebAuthn.Net.Storage.PostgreSql/)
- [WebAuthn.Net.Storage.MySql](https://www.nuget.org/packages/WebAuthn.Net.Storage.MySql/)
- [WebAuthn.Net.Storage.InMemory](https://www.nuget.org/packages/WebAuthn.Net.Storage.InMemory/)
- [WebAuthn.Net.OpenTelemetry](https://www.nuget.org/packages/WebAuthn.Net.OpenTelemetry/)

The demo applications in the [demo](https://github.com/dodobrands/WebAuthn.Net/tree/main/demo) directory are samples and are not intended for production use. Reports about them are still welcome through the same channel.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues, discussions or pull requests.**

Report all suspected vulnerabilities through GitHub's private vulnerability reporting by opening a new report at:

**<https://github.com/dodobrands/WebAuthn.Net/security/advisories/new>**

A private report is visible only to you and the repository maintainers until it is published. Please use this channel rather than email or any other means, so that every report is tracked in one place and stays confidential. Submitting a report requires a GitHub account; see GitHub's guide on [privately reporting a security vulnerability](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) for details on how the process works.

To help us triage the report quickly, please include as much of the following information as you can:

- Type of issue (for example signature verification bypass, challenge or origin validation flaw, attestation verification weakness, injection, denial of service)
- Affected package(s) and version(s)
- Full paths of the source file(s) related to the issue
- Location of the affected source code (tag, branch, commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

We prefer all communications to be in English.

## What to Expect

- We will acknowledge your report within 5 business days by commenting on it. If you do not receive an acknowledgement, please add a comment to your report to make sure it has not been missed.
- We will investigate the report, confirm the vulnerability and keep you informed of our progress in the report's comments.
- Once a fix is ready, we will release new versions of the affected packages on [NuGet](https://www.nuget.org/profiles/dodobrands) and publish the [security advisory](https://github.com/dodobrands/WebAuthn.Net/security/advisories) created from your report, requesting a CVE identifier where appropriate.
- We will credit you in the advisory unless you prefer to remain anonymous.

## Disclosure Policy

We follow the principle of coordinated vulnerability disclosure.

- Do not disclose the vulnerability publicly (including blog posts, social media, conference talks, mailing lists or third-party vulnerability databases) until a fix has been released and a disclosure date has been agreed with us.
- Give us a reasonable amount of time to investigate and fix the issue before any disclosure. We aim to resolve confirmed vulnerabilities within 90 days of the report.
- Act in good faith: do not exploit the vulnerability beyond what is necessary to demonstrate it, do not access, modify or destroy data that is not yours, and do not test against systems you do not own or operate, such as the public demo at [webauthn.dodo.dev](https://webauthn.dodo.dev). Use a local build of the library or of the demo applications instead.

Vulnerabilities in third-party dependencies (for example .NET, ASP.NET Core or libsodium) should be reported to the respective upstream projects. If such a vulnerability affects WebAuthn.Net specifically, please let us know as well.

Non-security bugs and feature requests should be reported through [GitHub issues](https://github.com/dodobrands/WebAuthn.Net/issues).
