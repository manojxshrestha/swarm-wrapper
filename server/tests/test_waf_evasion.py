"""Tests for WAF vendor signature validation and matching."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(scope="module")
def waf():
    import waf_evasion

    return waf_evasion


class TestCleanExternalSig:
    """Verify _clean_external_sig filters junk markers correctly."""

    def test_rejects_empty_markers(self, waf):
        sig = {"headers": [], "server": [], "body_patterns": [], "block_page_markers": [], "status_codes": []}
        assert waf._clean_external_sig(sig) is None

    def test_rejects_only_stopwords(self, waf):
        sig = {"headers": [], "server": [], "body_patterns": [], "block_page_markers": ["blocked", "page", "server", "error", "body"], "status_codes": []}
        assert waf._clean_external_sig(sig) is None

    def test_keeps_multi_word_phrases(self, waf):
        sig = {"headers": [], "server": [], "body_patterns": [], "block_page_markers": ["ray id", "cf-browser-verification"], "status_codes": []}
        result = waf._clean_external_sig(sig)
        assert result is not None
        assert "ray id" in result["block_page_markers"]

    def test_filters_stopwords_keeps_real(self, waf):
        sig = {"headers": [], "server": [], "body_patterns": [], "block_page_markers": ["powered", "blockpage", "body", "contains", "qianxin-waf", "header", "url", "wzws-ray"], "status_codes": []}
        result = waf._clean_external_sig(sig)
        assert result is not None
        markers = result["block_page_markers"]
        assert "qianxin-waf" in markers
        assert "wzws-ray" in markers
        for junk in ("powered", "blockpage", "body", "contains", "header", "url"):
            assert junk not in markers, f"'{junk}' should have been filtered"

    def test_keeps_three_char_specific(self, waf):
        sig = {"headers": ["x-amz-"], "server": [], "body_patterns": [], "block_page_markers": ["aws", "request blocked"], "status_codes": [403]}
        result = waf._clean_external_sig(sig)
        assert result is not None
        assert "aws" in result["block_page_markers"]
        assert "request blocked" in result["block_page_markers"]

    def test_structural_validation(self, waf):
        assert waf._clean_external_sig(None) is None
        assert waf._clean_external_sig("not a dict") is None
        assert waf._clean_external_sig({"headers": "not a list"}) is None


class TestMatchWaf:
    """Verify _match_waf doesn't false-positive on common text."""

    def test_no_false_positive_on_normal_html(self, waf):
        body = "<html><body><h1>Welcome</h1><p>Normal page with headers and body content and error codes.</p></body></html>"
        matches = waf._match_waf({"content-type": "text/html"}, body, 200)
        assert len(matches) == 0, f"Expected no WAF match, got {len(matches)}: {[m['waf'] for m in matches]}"

    def test_no_false_positive_on_common_words(self, waf):
        body = "The body of this page contains headers and footer information with error codes and reference numbers for url access denied"
        matches = waf._match_waf({"content-type": "text/plain"}, body, 200)
        assert len(matches) == 0, f"Expected no WAF match, got {len(matches)}"

    def test_generic_cdn_headers_not_flagged(self, waf):
        """M2: generic caching headers alone must NOT claim a WAF (was Fastly FP)."""
        headers = {"x-cache": "HIT", "x-served-by": "cache-xyz", "x-timer": "S123", "x-cache-hits": "2"}
        matches = waf._match_waf(headers, "<html>normal cached page</html>", 200)
        assert len(matches) == 0, f"Generic CDN headers must not match a WAF, got {[m['waf'] for m in matches]}"

    def test_real_fastly_block_still_detected(self, waf):
        """A genuine Fastly block (vendor body marker) is still detected."""
        body = "<html><body>Fastly error: unknown domain. Request blocked.</body></html>"
        matches = waf._match_waf({"x-served-by": "cache-1", "x-cache": "MISS"}, body, 403)
        assert any(m["waf"] == "fastly" for m in matches), "Real Fastly block should still be detected"

    def test_detects_cloudflare(self, waf):
        body = '<html><div class="cf-browser-verification">Ray ID: abc123</div></html>'
        matches = waf._match_waf({"server": "cloudflare", "cf-ray": "abc123"}, body, 403)
        cf = [m for m in matches if m["waf"] == "cloudflare"]
        assert len(cf) > 0, "Should detect Cloudflare"
        assert cf[0]["confidence"] >= 50, f"Cloudflare confidence too low: {cf[0]['confidence']}"

    def test_detects_aws_waf(self, waf):
        body = "<html><head><title>403 Forbidden</title></head><body>Request blocked by AWS WAF</body></html>"
        matches = waf._match_waf({"x-amz-request-id": "xyz", "content-type": "text/html"}, body, 403)
        aws = [m for m in matches if m["waf"] == "aws_waf"]
        assert len(aws) > 0, "Should detect AWS WAF"
        assert aws[0]["confidence"] >= 50

    def test_detects_akamai(self, waf):
        body = "<html><body>Access denied. Reference #12345.</body></html>"
        matches = waf._match_waf({"server": "AkamaiGHost"}, body, 403)
        akamai = [m for m in matches if m["waf"] == "akamai"]
        assert len(akamai) > 0, "Should detect Akamai"
