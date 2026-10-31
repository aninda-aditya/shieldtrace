# Changelog

All notable changes to ShieldTrace are documented here.
Format follows Keep a Changelog.
Versioning follows SemVer.

## [Unreleased]

## [0.1.0] - 2026-10-31

### Added
- Initial public release
- guardian.py - off-device alerting (SMS + ntfy), canary honeypot, environment baseline
- install.sh - one-command installer for Termux
- UNINSTALL.sh - safe removal (--purge also removes ~/shieldtrace)
- show_anchor.sh - external evidence-anchor helper

### Fixed
- shieldtrace_dashboard.py: /proc NUL parsing fixed
- evidence_integrity.py: anchor now written with mode 0o600
- thermal_monitor.py: lock_fd released on clean exit via finally
- thermal_monitor.py: escaped newline in print() fixed
- auto_audit.py: stale PID archive now atomic
- start_defense.sh: stale PID filename gains $$ suffix
- storage_monitor.py: new --accept flag rotates the baseline explicitly

### Security notes
- Local checkpoints are not attacker-proof; only an off-device anchor makes evidence-chain truncation detectable.
- cmdline verification proves a process exists with this argv, not that its code is unmodified.
