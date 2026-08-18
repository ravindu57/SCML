"""
Pytest configuration.

Point the test suite at its own database.

Two integration modules call ``Base.metadata.drop_all`` on teardown, which is
correct for a test fixture. But with ``DATABASE_URL=""`` — the documented way
to run the suite — settings fall back to ``sqlite+aiosqlite:///./trust_mediator.db``,
relative to the working directory. That is the same file a locally running
mediator uses, so running the tests from the repo root silently dropped every
table out from under it: the service stayed up, ``/health`` kept returning ok,
and every database-backed endpoint began returning 500. From a browser that
surfaces as "Failed to fetch" on every page, with nothing to suggest the tests
were responsible.

This must run before ``trust_mediator.config`` is imported, because settings
are a module-level singleton and ``db.base`` builds the engine from them at
import time. conftest is imported before test modules, so setting the variable
here is early enough.

``setdefault`` is not sufficient: the documented invocation passes
``DATABASE_URL=""``, so the key exists and setdefault would leave the empty
value in place, which is exactly the case that caused the problem.
"""

import os

if not os.environ.get("DATABASE_URL"):
    os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./trust_mediator.test.db"
