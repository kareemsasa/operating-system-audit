# Roadmap

This roadmap groups open issues by product area so each item has a clear purpose in the project. It is intentionally organized around capabilities rather than issue number or priority order.

## Schema and Compatibility

These items make audit output stable enough for automation, long-lived archives, and tooling that compares snapshots across versions.

- Normalized Concept Model for Cross-Platform Parity ([#29](https://github.com/kareemsasa/operating-system-audit/issues/29)) - Open; architecture, enhancement
- Versioned RunMeta schema ([#21](https://github.com/kareemsasa/operating-system-audit/issues/21)) - Open; architecture, enhancement, medium priority
- Schema Compatibility Policy and Migration Guarantees ([#23](https://github.com/kareemsasa/operating-system-audit/issues/23)) - Open; architecture, enhancement
- Structured drift summary (delta model) ([#22](https://github.com/kareemsasa/operating-system-audit/issues/22)) - Open; enhancement, medium priority, observability
- NDJSON Schema Contract and Validation Tests ([#24](https://github.com/kareemsasa/operating-system-audit/issues/24)) - Open; enhancement, testing
- Redaction Policy Spec ([#25](https://github.com/kareemsasa/operating-system-audit/issues/25)) - Open; enhancement, testing

## Linux Support

These items expand Linux coverage and keep platform behavior aligned with the existing cross-platform command manifest.

- Linux Support Roadmap ([#26](https://github.com/kareemsasa/operating-system-audit/issues/26)) - Open; enhancement, linux

## macOS Audits

These items deepen macOS coverage across privacy, security posture, persistence, backup state, and user-installed software.

- Add TCC/privacy permissions audit ([#1](https://github.com/kareemsasa/operating-system-audit/issues/1)) - Open; enhancement, high priority, mac
- Add sharing services audit ([#2](https://github.com/kareemsasa/operating-system-audit/issues/2)) - Open; enhancement, high priority, mac
- Add software update status audit ([#3](https://github.com/kareemsasa/operating-system-audit/issues/3)) - Open; enhancement, medium priority, mac
- Add FileVault details (unlock users, recovery key status) ([#4](https://github.com/kareemsasa/operating-system-audit/issues/4)) - Open; enhancement, medium priority, mac
- Add Secure Boot / startup disk security audit ([#5](https://github.com/kareemsasa/operating-system-audit/issues/5)) - Open; enhancement, low priority, mac
- Add browser extensions inventory ([#6](https://github.com/kareemsasa/operating-system-audit/issues/6)) - Open; enhancement, medium priority, mac
- Add installed applications inventory ([#7](https://github.com/kareemsasa/operating-system-audit/issues/7)) - Open; enhancement, medium priority, mac
- Add custom CA certificates audit ([#8](https://github.com/kareemsasa/operating-system-audit/issues/8)) - Open; enhancement, medium priority, mac
- Add Time Machine backup status audit ([#9](https://github.com/kareemsasa/operating-system-audit/issues/9)) - Open; enhancement, low priority, mac
- Add XProtect / MRT version audit ([#10](https://github.com/kareemsasa/operating-system-audit/issues/10)) - Open; enhancement, low priority, mac

## Reporting and Visualization

These items improve how humans inspect drift, failures, and trends after snapshots have been collected.

- Add diff visualization (HTML change report) ([#14](https://github.com/kareemsasa/operating-system-audit/issues/14)) - Open; enhancement, medium priority
- Port heatmap rendering from Python to Go ([#13](https://github.com/kareemsasa/operating-system-audit/issues/13)) - Open; enhancement, low priority

## Fleet and Comparison Features

These items support comparing multiple hosts, understanding relationships across systems, and measuring performance at larger scale.

- Cross-Host Compare (Fleet Topology) ([#28](https://github.com/kareemsasa/operating-system-audit/issues/28)) - Open; enhancement
- Performance Harness - Runtime Caps, Probe Timeouts, and Regression Detection ([#27](https://github.com/kareemsasa/operating-system-audit/issues/27)) - Open; enhancement, testing
