"""
Tests for the public API contract (trust_mediator/__init__.py, scml/__init__.py).

``__all__`` is the surface semantic versioning protects. These tests exist so
that shrinking it, renaming an export, or letting the ``scml`` alias drift from
the engine package fails here rather than in somebody's agent after an upgrade.
"""
from __future__ import annotations

import pytest

import scml
import trust_mediator


# The contract as of 1.0.0. Adding to this list is a minor version; removing
# from or renaming anything in it is a major version. Update deliberately.
EXPECTED_PUBLIC_API = {
    "SCMLClient",
    "AsyncSCMLClient",
    "TrustMediatorClient",
    "AsyncTrustMediatorClient",
    "MediationResult",
    "Verdict",
    "classify_decision",
    "TrustLabel",
    "SCMLError",
    "SCMLBlocked",
    "SCMLUnavailable",
    "MediationPipeline",
    "settings",
    "__version__",
}


class TestPublicSurface:
    def test_engine_exports_exactly_the_documented_contract(self):
        assert set(trust_mediator.__all__) == EXPECTED_PUBLIC_API

    def test_scml_alias_exports_the_same_names(self):
        """The alias must not drift from the engine; both are shipped."""
        assert set(scml.__all__) == set(trust_mediator.__all__)

    @pytest.mark.parametrize("name", sorted(EXPECTED_PUBLIC_API))
    def test_every_exported_name_actually_resolves(self, name):
        """An `__all__` entry that raises on access is worse than no entry."""
        assert getattr(trust_mediator, name) is not None
        assert getattr(scml, name) is not None

    def test_alias_and_engine_return_the_same_objects(self):
        assert scml.SCMLClient is trust_mediator.SCMLClient
        assert scml.Verdict is trust_mediator.Verdict

    def test_unknown_attribute_names_the_module_the_caller_used(self):
        """An alias blaming a package the caller never imported is confusing."""
        with pytest.raises(AttributeError, match="'scml'"):
            scml.no_such_name
        with pytest.raises(AttributeError, match="'trust_mediator'"):
            trust_mediator.no_such_name

    def test_dir_lists_the_public_api(self):
        assert set(dir(scml)) == EXPECTED_PUBLIC_API
        assert set(dir(trust_mediator)) == EXPECTED_PUBLIC_API


class TestVersionSingleSource:
    def test_alias_and_engine_report_one_version(self):
        assert scml.__version__ == trust_mediator.__version__

    def test_installed_metadata_matches_the_module(self):
        """
        pyproject reads `dynamic = ["version"]` from trust_mediator.__version__.
        If setuptools ever falls back to a hardcoded value these diverge.
        """
        from importlib.metadata import PackageNotFoundError, version

        try:
            installed = version("trust-mediator")
        except PackageNotFoundError:
            pytest.skip("package not installed in this environment")
        assert installed == trust_mediator.__version__


class TestLazyImports:
    """
    Laziness is a property of a *fresh interpreter*, so these run in a
    subprocess. Clearing sys.modules in-process would prove the same thing but
    leaves every later test importing a second copy of the package — it broke
    test_scanner_ml_gate, whose settings object stopped being the one the
    scanner had already bound.
    """

    @staticmethod
    def _run(code: str) -> str:
        import subprocess
        import sys

        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, timeout=60,
        )
        assert proc.returncode == 0, f"subprocess failed:\n{proc.stderr}"
        return proc.stdout.strip()

    def test_importing_the_package_does_not_pull_in_the_server_stack(self):
        """
        A client-only install has no core.pipeline. Importing the package must
        not reach for it, or `pip install trust-mediator` stops being a
        two-package install.
        """
        out = self._run(
            "import sys, trust_mediator;"
            "print('pipeline' if 'trust_mediator.core.pipeline' in sys.modules else 'clean')"
        )
        assert out == "clean"

    def test_touching_a_lazy_name_resolves_it(self):
        out = self._run(
            "import sys, trust_mediator;"
            "trust_mediator.MediationPipeline;"
            "print('loaded' if 'trust_mediator.core.pipeline' in sys.modules else 'missing')"
        )
        assert out == "loaded"

    def test_the_scml_alias_is_lazy_too(self):
        out = self._run(
            "import sys, scml;"
            "print('pipeline' if 'trust_mediator.core.pipeline' in sys.modules else 'clean')"
        )
        assert out == "clean"

    def test_client_is_eager_because_it_is_the_core_install(self):
        out = self._run(
            "import sys, trust_mediator;"
            "print('eager' if 'trust_mediator.client' in sys.modules else 'lazy')"
        )
        assert out == "eager"
