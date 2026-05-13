# .github/PULL_REQUEST_TEMPLATE.md

# ASF Pull Request

## Overview

Provide a concise summary of the proposed changes.

---

## Change Type

* [ ] Feature
* [ ] Security Enhancement
* [ ] Bug Fix
* [ ] Refactor
* [ ] Performance Optimization
* [ ] Infrastructure Change
* [ ] CI/CD Improvement
* [ ] Documentation Update

---

## Security Impact

Does this PR affect:

* authentication flow?
* JWT/session handling?
* Redis synchronization?
* AI threat analysis?
* distributed locking?
* authorization enforcement?
* middleware validation?

If yes, explain the impact clearly.

---

## Validation Checklist

* [ ] Lint passes
* [ ] Unit tests pass
* [ ] E2E tests pass
* [ ] Docker build succeeds
* [ ] No secrets exposed
* [ ] No critical vulnerabilities introduced
* [ ] Backward compatibility verified

---

## Infrastructure Notes

Describe:

* migration requirements
* environment changes
* Redis changes
* database changes
* deployment considerations

---

## Performance Considerations

Explain any impact on:

* latency
* concurrency
* Redis throughput
* authentication performance
* memory consumption

---

## Additional Context

Add any additional implementation details or architectural notes here.
