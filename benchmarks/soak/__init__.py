"""
Soak and fault-injection harness (PRD §8.3, NFR-AVAIL-01).

Measures availability of the mediation data plane under sustained load with
injected faults — the last PRD requirement with no measurement at all.

## What "available" means here

The distinction that makes this number meaningful: **rendering a decision is
availability, even when that decision is a denial.** §9 says a mediator that
cannot verify a tool call must deny it, so a deny during a database outage is
the system working exactly as specified — counting it as downtime would
penalise correct behaviour and reward a mediator that failed open.

    available    = the caller got a decision (allow / deny / quarantine / block)
    UNAVAILABLE  = an exception escaped, or the call timed out

Both are reported, plus the fail-closed rate during faults, so degradation is
visible without being confused for an outage.

Usage:
    python -m benchmarks.soak --duration 60
    python -m benchmarks.soak --duration 300 --format both --out benchmarks/results

**This module deliberately re-exports nothing.** `python -m benchmarks.soak`
imports this file before `__main__.main()` can pin DATABASE_URL, and
`trust_mediator.db.base` builds its engine at import time from settings — an
import here would silently run the soak against the application database.
"""
