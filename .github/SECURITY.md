# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities by email to **me@juntaki.com**
rather than opening a public issue. Include as much detail as you can
(affected component, reproduction steps, potential impact) so it can be
triaged quickly. You should get an acknowledgment within a few days.

## Project status

YadoriLink is pre-1.0 and under active development. Until a 1.0 release:

- The CLI, IPC, and sync-protocol interfaces are not stable and may
  change between versions without a deprecation period.
- Security-sensitive code paths are still evolving. Review the source and
  release notes carefully before relying on YadoriLink for sensitive data.

## Scope

This security policy covers the code published in this repository: the
CLI, daemon, sync engine, transport/relay, local storage, installers, and
shell integrations. Coordination-service deployments and hosted-service
operations are outside the scope of this repository.
