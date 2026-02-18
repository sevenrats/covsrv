import hashlib

from fastapi import Response


def badge_color(percent: float | None) -> str:
    # shields-ish colors
    if percent is None:
        return "#9f9f9f"  # grey
    p = float(percent)
    if p < 50.0:
        return "#e05d44"  # red
    if p < 75.0:
        return "#fe7d37"  # orange
    if p < 90.0:
        return "#dfb317"  # yellow
    return "#4c1"  # green


def _escape_xml(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _text_px_width(s: str) -> int:
    """
    Approximate width for DejaVu Sans-ish at 11px.
    Good enough for badges without pulling in a font engine.
    """
    return max(0, int(len(s) * 6.2) + 10)


def render_badge_svg(label: str, message: str, color: str) -> str:
    label = _escape_xml(label)
    message = _escape_xml(message)

    # widths
    lw = _text_px_width(label)
    mw = _text_px_width(message)
    w = lw + mw
    h = 20

    # text anchor positions
    lx = lw // 2
    mx = lw + (mw // 2)

    # classic badge SVG (similar to shields)
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" role="img" aria-label="{label}: {message}">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{w}" height="{h}" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{lw}" height="{h}" fill="#555"/>
    <rect x="{lw}" width="{mw}" height="{h}" fill="{color}"/>
    <rect width="{w}" height="{h}" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle"
     font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="{lx}" y="14">{label}</text>
    <text x="{mx}" y="14">{message}</text>
  </g>
</svg>
"""


def svg_response(svg: str, cache_control: str, etag_seed: str) -> Response:
    etag = hashlib.sha256(etag_seed.encode("utf-8")).hexdigest()
    return Response(
        content=svg,
        media_type="image/svg+xml; charset=utf-8",
        headers={
            "Cache-Control": cache_control,
            "ETag": f'"{etag}"',
        },
    )


def coverage_message(percent: float | None, decimals: int = 1) -> str:
    if percent is None:
        return "unknown"
    p = float(percent)
    # normalize
    if p < 0:
        p = 0.0
    if p > 100:
        p = 100.0
    return f"{p:.{decimals}f}%"
