"""Unit tests for Output Redaction (§6.6)."""
import pytest
from trust_mediator.modules.output_redaction.redactor import OutputRedactor


class TestOutputRedactor:
    def setup_method(self):
        self.redactor = OutputRedactor()

    def test_redacts_email(self):
        r = self.redactor.redact("Contact us at support@example.com for help.")
        assert "support@example.com" not in r.content
        assert "[REDACTED:EMAIL]" in r.content
        assert any(x["type"] == "email" for x in r.redactions_applied)

    def test_redacts_phone(self):
        r = self.redactor.redact("Call me at 555-867-5309 anytime.")
        assert "555-867-5309" not in r.content
        assert "[REDACTED:PHONE]" in r.content

    def test_redacts_api_key(self):
        r = self.redactor.redact("Use api_key=sk-abc123456789012345678901234 for authentication.")
        assert "sk-abc123456789012345678901234" not in r.content

    def test_redacts_password(self):
        r = self.redactor.redact("The password=SuperSecret123! was exposed.")
        assert "SuperSecret123" not in r.content

    def test_redacts_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        r = self.redactor.redact(f"Token: {jwt}")
        assert jwt not in r.content
        assert "[REDACTED:JWT]" in r.content

    def test_benign_content_unchanged(self):
        text = "The meeting is scheduled for Monday at 10am in Conference Room B."
        r = self.redactor.redact(text)
        assert r.content == text
        assert len(r.redactions_applied) == 0
        assert r.action_allowed is True

    def test_high_entropy_secret_detected(self):
        # 40-char high-entropy string (looks like an AWS secret)
        secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        r = self.redactor.redact(f"AWS secret: {secret}")
        assert secret not in r.content

    def test_data_flow_block(self):
        redactor = OutputRedactor(policy_config={
            "pii_patterns_enabled": True,
            "entropy_threshold": 4.5,
            "protected_classes": ["pii"],
            "data_flow_rules": {"pii": ["internal_only"]},
        })
        r = redactor.redact(
            "User data here",
            destination="external_api",
            data_class_labels=["pii"],
        )
        assert r.blocked is True
        assert r.action_allowed is False

    def test_data_flow_allowed(self):
        redactor = OutputRedactor(policy_config={
            "pii_patterns_enabled": False,
            "entropy_threshold": 4.5,
            "protected_classes": ["pii"],
            "data_flow_rules": {"pii": ["user", "internal"]},
        })
        r = redactor.redact("Some data", destination="user", data_class_labels=["pii"])
        assert r.blocked is False
        assert r.action_allowed is True

    def test_multiple_redactions_applied(self):
        text = "Email: alice@example.com, Phone: 555-123-4567, password=hunter2"
        r = self.redactor.redact(text)
        assert len(r.redactions_applied) >= 3
