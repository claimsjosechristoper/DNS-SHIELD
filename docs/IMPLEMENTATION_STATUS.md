# DNS-SHIELD implementation status

Updated: 2026-10-12

## Verified in this workspace

* The development launcher starts the DNS gateway on UDP and TCP
  `127.0.0.1:5353`.
* The local FastAPI dashboard responds at `http://127.0.0.1:8000/`.
* The gateway policy engine evaluates requests before forwarding.
* Blocked requests have tests asserting that the controlled upstream is not
  contacted.
* TCP request handling now reads fragmented two-byte length prefixes and
  fragmented DNS payloads exactly.
* UDP and TCP request work is bounded by a shared worker pool rather than one
  unbounded thread per request.
* Listener startup cleans up sockets when the second bind fails.
* The launcher and desktop entry point no longer print the administrator API
  key or open a browser automatically.
* API and dashboard responses no longer expose the legacy block-rate
  percentage field.
* Windows SCM service class, bounded lifecycle runtime, health states,
  authenticated narrow local request protocol, and inert install/remove/
  diagnostic scripts are present.

## Not yet verified or implemented

* Genuine Windows Service Control Manager registration, recovery actions, and
  packaged service execution have not been activated or tested on a clean
  Windows machine.
* An authenticated, narrow named-pipe transport and restrictive Windows
  storage ACL code are wired into the service runtime, but have not been
  activated or exercised through SCM on this laptop.
* A native desktop UI with tray support is not implemented.
* Transactional Windows IPv4/IPv6 adapter DNS configuration and restoration.
* Protection-state health checks that prove Windows DNS is routed through the
  service.
* IPv6 DNS listeners and end-to-end IPv6 integration tests.
* Windows Filtering Platform controls for direct DNS and encrypted-DNS
  bypasses.
* Installer, code signing, upgrade, uninstall, and clean-machine tests.
* Hosted management, enrollment, tenant isolation, and authenticated policy
  distribution.
* Clean Windows reboot, sleep/resume, VPN, network-change, and recovery tests.

## Verification notes

The API and dashboard no longer return or render `block_rate_percentage`.
Legacy numerical risk-score fields remain in the offline detection and
forensics modules and their tests; those modules are not used by the gateway
decision path and have not been silently rewritten in this phase.

## Evidence categories

* **Unit/controlled tests:** existing Python tests and controlled local
  upstream tests.
* **This laptop:** local dashboard startup has been verified on loopback.
* **Clean-machine tests:** not run.
* **Windows integration:** not run; no adapter, firewall, or service changes
  have been activated.

## Current limitations

The current executable is a development launcher, not an installable Windows
protection product. It does not automatically change Windows DNS settings,
does not claim encrypted-DNS or VPN enforcement, and should not be exposed
outside loopback.
