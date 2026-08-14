# Soak and fault injection — NFR-AVAIL-01

- Duration: `27.41s`
- Python 3.12.3 on Linux-6.14.0-37-generic-x86_64-with-glibc2.39

## What is being measured

Availability here is **the caller received a decision**, including a
denial. §9 requires a mediator that cannot verify a tool call to deny
it, so a deny during a database outage is correct behaviour, not
downtime — counting it as downtime would reward a mediator that failed
open. A call counts as unavailable only when an exception escaped or
the call timed out.

## Headline

| Metric | Measured | Target | Result |
|---|---:|---:|---|
| Availability (NFR-AVAIL-01) | 100.000% | ≥ 99.9% | PASS |
| Calls | 10666 | — | |
| Decisions rendered | 10666 | — | |
| Latency p50 | 0.202 ms | — | |
| Latency p95 | 44.877 ms | < 400 ms | PASS |

## Per-phase breakdown

| Phase | Calls | Availability | Verdicts | Escaped errors |
|---|---:|---:|---|---|
| `healthy` | 2014 | 100.00% | allow=530, deny.rate_limit=477, persist=514, released=493 | none |
| `scanner_down` | 450 | 100.00% | allow=112, deny.rate_limit=113, persist=114, released=111 | none |
| `policy_store_down` | 314 | 100.00% | allow=78, mediator_error=79, persist=80, released=77 | none |
| `memory_store_down` | 7468 | 100.00% | allow=1867, deny.rate_limit=1867, quarantine=1867, released=1867 | none |
| `redactor_down` | 210 | 100.00% | allow=52, blocked=51, deny.rate_limit=53, persist=54 | none |
| `audit_store_down` | 198 | 100.00% | allow=49, deny.rate_limit=50, persist=51, released=48 | none |
| `scanner_slow` | 12 | 100.00% | allow=3, deny.rate_limit=3, persist=4, released=2 | none |

## Recovery after each fault cleared

| Fault | Seconds to first decision |
|---|---:|
| `scanner_down` | 0.0005 |
| `policy_store_down` | 0.0002 |
| `memory_store_down` | 0.0001 |
| `redactor_down` | 0.0002 |
| `audit_store_down` | 0.0002 |
| `scanner_slow` | 0.0006 |

## Reading this honestly

Faults are injected into a live in-process pipeline, so this measures
the mediator's own fault handling — not the availability of a deployed
service behind a load balancer, and not network partitions, disk
exhaustion or OOM. A passing number here means the data plane keeps
rendering decisions when a dependency breaks; it is not a production
uptime SLO and must not be quoted as one.
