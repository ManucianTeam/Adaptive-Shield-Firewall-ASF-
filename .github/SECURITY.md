# .github/SECURITY.md

# Security Policy

## Supported Versions

The following versions of ASF (Adaptive Shield Firewall) currently receive
security updates and maintenance support.

| Version | Supported |
| ------- | --------- |
| latest  | ✅         |
| develop | ✅         |
| legacy  | ❌         |

---

## Reporting A Vulnerability

If you discover a security vulnerability, please report it responsibly.

DO NOT create public GitHub issues for security-sensitive reports.

Instead, contact the maintainers directly with:

* vulnerability description
* reproduction steps
* affected components
* proof-of-concept (if applicable)
* potential impact assessment

---

## Security Scope

ASF is a security-oriented infrastructure platform focused on:

* adaptive authentication
* distributed session security
* AI-assisted anomaly detection
* Zero Trust enforcement
* JWT security pipelines
* Redis synchronization layers
* distributed API protection

Security reports involving the following areas are prioritized:

* authentication bypass
* privilege escalation
* session hijacking
* token leakage
* remote code execution
* distributed lock bypass
* race-condition exploitation
* deserialization attacks
* SSRF / injection vulnerabilities
* cache poisoning
* replay attacks

---

## Responsible Disclosure

Please allow reasonable time for investigation and remediation before public disclosure.

Security patches are validated through:

* CI/CD security workflows
* CodeQL analysis
* Trivy vulnerability scanning
* dependency auditing
* static analysis pipelines

---

## Security Philosophy

ASF follows a defense-in-depth architecture emphasizing:

* minimal attack surface
* strict validation boundaries
* distributed isolation
* secure-by-default infrastructure
* runtime anomaly detection
* layered authentication enforcement

---

## Infrastructure Security

Recommended deployment practices:

* run containers as non-root
* isolate Redis and PostgreSQL networks
* enable TLS termination
* rotate JWT secrets regularly
* restrict internal service exposure
* enable centralized logging and monitoring

---

## Contact

Security-related communications should remain confidential until remediation is complete.
