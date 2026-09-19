# Security Policy

## Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 3.x.x   | ✅ Active support  |
| 2.x.x   | ⚠️  Critical fixes only |
| 1.x.x   | ❌ Not supported   |
| < 1.0   | ❌ Not supported   |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, report them via one of the following:

1. **GitHub Security Advisory** (preferred):
   [Open a private advisory](https://github.com/milesmaro2006-dev/spider-forge/security/advisories/new)

2. **Email**: spidey@redteam.local

### What to include

- **Type of vulnerability** (e.g., RCE, injection, path traversal)
- **Full paths of source files** related to the issue
- **Location of the affected code** (tag, branch, commit, or URL)
- **Step-by-step instructions** to reproduce
- **Proof-of-concept or exploit code** (if possible)
- **Impact** including how an attacker might exploit it

### What to expect

| Timeline | Action |
|---|---|
| Within 48 hours | Acknowledgment of your report |
| Within 5 days | Initial assessment and severity classification |
| Within 30 days | Patch released (for confirmed vulnerabilities) |
| After patch | Public disclosure coordinated with you |

### Safe Harbor

We consider security research conducted in accordance with this policy to be:

- Authorized concerning any applicable anti-hacking laws
- Authorized concerning any relevant anti-circumvention laws
- Exempt from restrictions in our Terms of Service

We will not pursue civil action or initiate a complaint to law enforcement
for accidental, good-faith violations of this policy.

## Scope

**In scope:**

- The SpiderForge Python package (`spiderforge/`)
- The web dashboard (`backend/`, `frontend/`)
- The CLI (`spiderforge/cli/`)
- The installation scripts (`scripts/`)

**Out of scope:**

- Vulnerabilities in third-party dependencies
  (report them upstream, but notify us)
- Vulnerabilities in targets that SpiderForge is used against
- Social engineering attacks against maintainers
- DoS attacks

## Legal Notice

SpiderForge is a security tool intended for **authorized testing only**.
Do not use it against systems you do not own or have explicit permission to
test. Misuse may violate laws.

## Credits

We publicly credit reporters in release notes (unless you request anonymity).

Thank you for helping keep SpiderForge and its users safe! 🕷️
