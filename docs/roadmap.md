# Roadmap

This roadmap groups planned work by product area so each issue has a clear purpose in the project. It is intentionally organized around capabilities rather than priority order.

## Schema and Compatibility

These items make audit output stable enough for automation, long-lived archives, and tooling that compares snapshots across versions.

- Versioned RunMeta schema ([#21](https://github.com/kareemsasa/operating-system-audit/issues/21))
- Schema compatibility policy and migration guarantees ([#23](https://github.com/kareemsasa/operating-system-audit/issues/23))
- Structured drift summary / delta model ([#22](https://github.com/kareemsasa/operating-system-audit/issues/22))
- NDJSON schema contract and validation tests ([#24](https://github.com/kareemsasa/operating-system-audit/issues/24))
- Redaction policy spec ([#25](https://github.com/kareemsasa/operating-system-audit/issues/25))
- Normalized concept model ([#29](https://github.com/kareemsasa/operating-system-audit/issues/29))

## Linux Support

These items expand Linux coverage and keep platform behavior aligned with the existing cross-platform command manifest.

- Linux support roadmap ([#26](https://github.com/kareemsasa/operating-system-audit/issues/26))

## macOS Audits

These items deepen macOS coverage across privacy, security posture, persistence, backup state, and user-installed software.

- Add TCC/privacy permissions audit ([#1](https://github.com/kareemsasa/operating-system-audit/issues/1))
- Add sharing services audit ([#2](https://github.com/kareemsasa/operating-system-audit/issues/2))
- Add software update status audit ([#3](https://github.com/kareemsasa/operating-system-audit/issues/3))
- Add FileVault details ([#4](https://github.com/kareemsasa/operating-system-audit/issues/4))
- Add Secure Boot / startup disk security audit ([#5](https://github.com/kareemsasa/operating-system-audit/issues/5))
- Add custom CA certificates audit ([#8](https://github.com/kareemsasa/operating-system-audit/issues/8))
- Add XProtect / MRT version audit ([#10](https://github.com/kareemsasa/operating-system-audit/issues/10))
- Add Time Machine backup status audit ([#9](https://github.com/kareemsasa/operating-system-audit/issues/9))
- Add installed applications inventory ([#7](https://github.com/kareemsasa/operating-system-audit/issues/7))
- Add browser extensions inventory ([#6](https://github.com/kareemsasa/operating-system-audit/issues/6))

## Reporting and Visualization

These items improve how humans inspect drift, failures, and trends after snapshots have been collected.

- Add diff visualization / HTML change report ([#14](https://github.com/kareemsasa/operating-system-audit/issues/14))
- Port heatmap rendering from Python to Go ([#13](https://github.com/kareemsasa/operating-system-audit/issues/13))

## Fleet and Comparison Features

These items support comparing multiple hosts, understanding relationships across systems, and measuring performance at larger scale.

- Cross-host compare / fleet topology ([#28](https://github.com/kareemsasa/operating-system-audit/issues/28))
- Performance harness ([#27](https://github.com/kareemsasa/operating-system-audit/issues/27))
