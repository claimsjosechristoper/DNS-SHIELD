# DNS-SHIELD Windows architecture

## Scope

DNS-SHIELD is a local DNS filtering service for Windows 11 x64. It makes
deterministic `ALLOW` or `BLOCK` decisions for DNS requests received by its
local listener. It is not a general network firewall and does not block
malware that uses direct IP connections, its own VPN, or an independently
configured encrypted-DNS client.

The current development listener is `127.0.0.1:5353`; changing Windows
adapter DNS settings to route traffic to it is intentionally not performed by
the application yet.

## Components and trust boundaries

* **DNS service (future SCM service):** the privileged component that owns DNS
  listeners, policy evaluation, upstream forwarding, bounded caching, and
  local event storage.
* **Desktop application:** an unelevated user interface. It must request
  narrowly scoped operations from the service and must not own enforcement.
* **Local IPC:** authenticated, local-only control traffic. A Windows named
  pipe with an explicit ACL is the planned production transport. The current
  HTTP API is development-only and must not be exposed beyond loopback.
* **Upstream resolvers:** untrusted network dependencies. Responses must be
  validated and timeouts must produce `SERVFAIL`, never fabricated success.
* **Management backend (future):** optional control-plane synchronization. DNS
  decisions continue using the last valid local policy when the backend is
  unavailable.

## Data and failure paths

Policy checks occur before cache lookup. A blocked request is answered locally
and is never forwarded. An upstream timeout or malformed response produces an
explicit failure response. Service health must reflect enforcement checks, not
merely process liveness.

Planned health states:

* `PROTECTED`: listener, policy, upstream health checks, and configured DNS
  routing are verified.
* `DEGRADED`: the service is running but one required protection check is not
  passing.
* `DISABLED`: protection was intentionally disabled.
* `ERROR`: startup or configuration failed.

## Platform limitations

* IPv4 loopback is implemented in the current gateway. IPv6 listener support
  and Windows adapter routing are pending.
* DNS over HTTPS, DNS over TLS, QUIC, VPN resolvers, and direct-IP traffic are
  outside the current enforcement path. Blocking all HTTPS is not an
  acceptable substitute.
* DNSSEC validation is not implemented and is not claimed.
* A local administrator or custom application can bypass local DNS policy.

## Privilege and storage strategy

The service should run under a dedicated least-privilege service identity.
Configuration and state belong under a machine-wide application-data directory
with ACLs that allow the service to write and standard users to read only
sanitized status data. Secrets, private event history, and administrator
credentials must never be printed or included in an installer.

## Activation boundary

Changing adapter DNS settings, firewall rules, or SCM registration changes this
machine and requires an explicit user-approved activation step. Before that
step, the implementation must show the exact mutations and a tested rollback
procedure.
