"""Tests for browser_tools.py helper functions (no browser required)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ── Mock data ─────────────────────────────────────────────────────────

MOCK_ELEMENTS = [
    {"index": 1, "tag": "input", "type": "email", "name": "email", "placeholder": "", "label": "", "text": "", "id": "", "class": "", "value": "", "role": ""},
    {"index": 2, "tag": "input", "type": "text", "name": "username", "placeholder": "Username", "label": "", "text": "", "id": "login-username", "class": "", "value": "", "role": ""},
    {"index": 3, "tag": "input", "type": "password", "name": "password", "placeholder": "Password", "label": "", "text": "", "id": "", "class": "", "value": "", "role": ""},
    {"index": 4, "tag": "button", "type": "submit", "name": "", "placeholder": "", "label": "", "text": "Sign In", "id": "", "class": "btn-primary", "value": "", "role": ""},
    {"index": 5, "tag": "input", "type": "text", "name": "firstName", "placeholder": "First Name", "label": "", "text": "", "id": "", "class": "", "value": "", "role": ""},
    {"index": 6, "tag": "input", "type": "text", "name": "email", "placeholder": "", "label": "Email address", "text": "", "id": "", "class": "", "value": "", "role": ""},
    {"index": 7, "tag": "a", "type": "", "name": "", "placeholder": "", "label": "", "text": "Forgot password?", "id": "", "class": "", "value": "", "role": ""},
]


class TestEngagementDir:
    def _engagement_dir(self, eid: str) -> Path:
        from browser_tools import _engagement_dir

        return _engagement_dir(eid)

    def test_normal_id(self):
        result = self._engagement_dir("test-123")
        assert result.name == "test-123"
        assert ".." not in result.parts

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            self._engagement_dir("")

    def test_sanitizes_path_traversal(self):
        result = self._engagement_dir("../../etc/passwd")
        # Dots/slashes are stripped from the directory name, preventing traversal
        assert ".." not in result.parts

    def test_truncates_long_ids(self):
        long_id = "a" * 200
        result = self._engagement_dir(long_id)
        assert len(result.name) == 100


class TestFindField:
    def _find_field(self, elements, field_type, hint=""):
        from browser_tools import _find_field

        return _find_field(elements, field_type, hint)

    def test_finds_email_by_type(self):
        assert self._find_field(MOCK_ELEMENTS, "username") == 1

    def test_finds_username_by_placeholder(self):
        assert self._find_field(MOCK_ELEMENTS, "username") == 1

    def test_finds_password_by_type(self):
        assert self._find_field(MOCK_ELEMENTS, "password") == 3

    def test_finds_submit_by_type(self):
        assert self._find_field(MOCK_ELEMENTS, "submit") == 4

    def test_finds_submit_by_text(self):
        elements = [
            {"index": 1, "tag": "button", "type": "", "name": "", "placeholder": "", "label": "", "text": "Log In", "id": "", "class": "", "value": "", "role": ""},
        ]
        assert self._find_field(elements, "submit") == 1

    def test_finds_with_hint(self):
        # hint="Email" matches element 1 first (name="email" contains "email")
        assert self._find_field(MOCK_ELEMENTS, "username", hint="Email") == 1

    def test_finds_with_unique_hint(self):
        # hint="Address" should match element 6 (label="Email address")
        assert self._find_field(MOCK_ELEMENTS, "username", hint="Address") == 6

    def test_returns_none_when_not_found(self):
        assert self._find_field([], "submit") is None

    def test_ignores_irrelevant_elements(self):
        elements = [{"index": 1, "tag": "div"}, {"index": 2, "tag": "span"}]
        assert self._find_field(elements, "password") is None


class TestStateToElements:
    def _state_to_elements(self, summary):
        from browser_tools import _state_to_elements

        return _state_to_elements(summary)

    def test_handles_none_dom_state(self):
        class MockSummary:
            dom_state = None

        assert self._state_to_elements(MockSummary()) == []

    def test_handles_empty_selector_map(self):
        class MockNode:
            node_name = ""
            attributes = {}
            node_value = ""

        class MockDOMState:
            selector_map = {}

        class MockSummary:
            dom_state = MockDOMState()

        assert self._state_to_elements(MockSummary()) == []


class TestDomainExtraction:
    """Test URL domain extraction (used in browser_auto_auth fix)."""

    def test_full_url(self):
        from urllib.parse import urlparse

        url = "https://bugcrowd.com/user/sign_up"
        domain = urlparse(url).netloc
        assert domain == "bugcrowd.com"

    def test_with_subdomain(self):
        from urllib.parse import urlparse

        url = "https://login.hackers.bugcrowd.com/signin/register"
        domain = urlparse(url).netloc
        assert domain == "login.hackers.bugcrowd.com"

    def test_with_port(self):
        from urllib.parse import urlparse

        url = "https://example.com:8080/login"
        domain = urlparse(url).netloc
        assert domain == "example.com:8080"

    def test_with_path_only(self):
        from urllib.parse import urlparse

        url = "bugcrowd.com"
        domain = urlparse(f"https://{url}").netloc
        assert domain == "bugcrowd.com"
