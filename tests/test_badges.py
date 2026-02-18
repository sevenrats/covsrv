"""Tests for covsrv.badges module."""

from __future__ import annotations

from fastapi import Response

from covsrv.badges.badges import (
    _escape_xml,
    _text_px_width,
    badge_color,
    coverage_message,
    render_badge_svg,
    svg_response,
)

# -----------------------------------------------------------------------
# badge_color
# -----------------------------------------------------------------------


class TestBadgeColor:
    def test_none_returns_grey(self):
        assert badge_color(None) == "#9f9f9f"

    def test_below_50_returns_red(self):
        assert badge_color(0.0) == "#e05d44"
        assert badge_color(49.9) == "#e05d44"

    def test_50_to_75_returns_orange(self):
        assert badge_color(50.0) == "#fe7d37"
        assert badge_color(74.9) == "#fe7d37"

    def test_75_to_90_returns_yellow(self):
        assert badge_color(75.0) == "#dfb317"
        assert badge_color(89.9) == "#dfb317"

    def test_90_plus_returns_green(self):
        assert badge_color(90.0) == "#4c1"
        assert badge_color(100.0) == "#4c1"

    def test_exact_boundaries(self):
        """Verify boundary values fall in the right bucket."""
        assert badge_color(49.999) == "#e05d44"
        assert badge_color(50.0) == "#fe7d37"
        assert badge_color(74.999) == "#fe7d37"
        assert badge_color(75.0) == "#dfb317"
        assert badge_color(89.999) == "#dfb317"
        assert badge_color(90.0) == "#4c1"


# -----------------------------------------------------------------------
# _escape_xml
# -----------------------------------------------------------------------


class TestEscapeXml:
    def test_ampersand(self):
        assert _escape_xml("a&b") == "a&amp;b"

    def test_less_than(self):
        assert _escape_xml("a<b") == "a&lt;b"

    def test_greater_than(self):
        assert _escape_xml("a>b") == "a&gt;b"

    def test_double_quote(self):
        assert _escape_xml('a"b') == "a&quot;b"

    def test_single_quote(self):
        assert _escape_xml("a'b") == "a&apos;b"

    def test_no_escaping_needed(self):
        assert _escape_xml("hello world") == "hello world"

    def test_multiple_special(self):
        assert _escape_xml('<"&">') == "&lt;&quot;&amp;&quot;&gt;"

    def test_empty(self):
        assert _escape_xml("") == ""


# -----------------------------------------------------------------------
# _text_px_width
# -----------------------------------------------------------------------


class TestTextPxWidth:
    def test_empty_string(self):
        assert _text_px_width("") == 10  # max(0, 0 + 10)

    def test_positive_width(self):
        w = _text_px_width("hello")
        assert w > 0
        assert isinstance(w, int)

    def test_longer_string_wider(self):
        assert _text_px_width("longer text") > _text_px_width("hi")


# -----------------------------------------------------------------------
# render_badge_svg
# -----------------------------------------------------------------------


class TestRenderBadgeSvg:
    def test_returns_valid_svg(self):
        svg = render_badge_svg("coverage", "85.0%", "#4c1")
        assert svg.startswith("<svg")
        assert "</svg>" in svg
        assert "coverage" in svg
        assert "85.0%" in svg

    def test_escapes_special_characters_in_label(self):
        svg = render_badge_svg("<script>", "ok", "#4c1")
        assert "<script>" not in svg
        assert "&lt;script&gt;" in svg

    def test_escapes_special_characters_in_message(self):
        svg = render_badge_svg("label", "a&b", "#4c1")
        assert "a&amp;b" in svg

    def test_svg_has_role_img(self):
        svg = render_badge_svg("cov", "90%", "#4c1")
        assert 'role="img"' in svg

    def test_svg_has_aria_label(self):
        svg = render_badge_svg("cov", "90%", "#4c1")
        assert 'aria-label="cov: 90%"' in svg


# -----------------------------------------------------------------------
# svg_response
# -----------------------------------------------------------------------


class TestSvgResponse:
    def test_returns_response_with_svg_content_type(self):
        resp = svg_response("<svg/>", "public, max-age=60", "seed")
        assert isinstance(resp, Response)
        assert resp.media_type == "image/svg+xml; charset=utf-8"

    def test_cache_control_header(self):
        resp = svg_response("<svg/>", "public, max-age=3600", "seed")
        assert resp.headers["Cache-Control"] == "public, max-age=3600"

    def test_etag_header_is_deterministic(self):
        r1 = svg_response("<svg/>", "no-cache", "same-seed")
        r2 = svg_response("<svg/>", "no-cache", "same-seed")
        assert r1.headers["ETag"] == r2.headers["ETag"]

    def test_etag_differs_for_different_seeds(self):
        r1 = svg_response("<svg/>", "no-cache", "seed-a")
        r2 = svg_response("<svg/>", "no-cache", "seed-b")
        assert r1.headers["ETag"] != r2.headers["ETag"]

    def test_body_is_svg(self):
        resp = svg_response("<svg>hi</svg>", "no-cache", "s")
        assert resp.body == b"<svg>hi</svg>"


# -----------------------------------------------------------------------
# coverage_message
# -----------------------------------------------------------------------


class TestCoverageMessage:
    def test_none_returns_unknown(self):
        assert coverage_message(None) == "unknown"

    def test_zero(self):
        assert coverage_message(0.0) == "0.0%"

    def test_normal_value(self):
        assert coverage_message(85.5) == "85.5%"

    def test_hundred(self):
        assert coverage_message(100.0) == "100.0%"

    def test_negative_clamped(self):
        assert coverage_message(-5.0) == "0.0%"

    def test_over_100_clamped(self):
        assert coverage_message(150.0) == "100.0%"

    def test_custom_decimals(self):
        assert coverage_message(85.555, decimals=2) == "85.56%"
        assert coverage_message(85.555, decimals=0) == "86%"

    def test_none_with_decimals(self):
        assert coverage_message(None, decimals=3) == "unknown"
