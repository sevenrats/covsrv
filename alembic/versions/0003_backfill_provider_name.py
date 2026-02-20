"""Backfill provider_name for legacy reports.

Old reports have provider_name = '' and provider_url set to the hardcoded
default ('https://github.com') regardless of where the repo actually lives.
When the TOML config is present we can resolve the correct provider_name
from the configured provider URLs and update the rows.

If the provider_url matches a configured provider URL exactly, we use that.
Otherwise, when there is exactly one provider configured, we assume all
legacy reports belong to it (the single-forge deployment case).

Revision ID: 0003
Revises: 0002
Create Date: 2026-02-20
"""

from __future__ import annotations

import os
from pathlib import Path

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: str = "0002"
branch_labels: str | None = None
depends_on: str | None = None


def _load_config():
    """Attempt to load the ConfigManager from the TOML config file.

    Returns ``None`` if the config file is not present or cannot be parsed.
    """
    try:
        from covsrv.config import ConfigManager
    except Exception:
        return None

    base_dir = Path(os.environ.get("COVSRV_DATA", ".")).resolve()
    config_path = Path(os.environ.get("COVSRV_CONF", str(base_dir / "config.toml")))
    if not config_path.is_file():
        return None

    try:
        return ConfigManager.from_file(config_path)
    except Exception:
        return None


def upgrade() -> None:
    cfg = _load_config()
    if cfg is None:
        # No config file — nothing to backfill.
        return

    providers = cfg.providers  # dict[str, ProviderEntry]
    if not providers:
        return

    conn = op.get_bind()

    # Build url → name mapping for all configured providers.
    url_to_name: dict[str, str] = {}
    for name, entry in providers.items():
        url_to_name[entry.url.rstrip("/")] = name

    # First pass: match by exact provider_url.
    for url, pname in url_to_name.items():
        conn.execute(
            sa.text(
                "UPDATE reports SET provider_name = :pname "
                "WHERE (provider_name IS NULL OR provider_name = '') "
                "AND RTRIM(provider_url, '/') = :url"
            ),
            {"pname": pname, "url": url},
        )

    # Second pass: if there is exactly one provider, assign remaining
    # empty rows to it (covers stale default URLs like 'https://github.com').
    if len(providers) == 1:
        sole_name = next(iter(providers))
        conn.execute(
            sa.text(
                "UPDATE reports SET provider_name = :pname "
                "WHERE (provider_name IS NULL OR provider_name = '')"
            ),
            {"pname": sole_name},
        )


def downgrade() -> None:
    # Reversing the backfill: reset provider_name back to empty.
    conn = op.get_bind()
    conn.execute(sa.text("UPDATE reports SET provider_name = ''"))
