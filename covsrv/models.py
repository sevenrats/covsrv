"""SQLAlchemy ORM models for covsrv."""

from __future__ import annotations

from sqlalchemy import Float, Index, Integer, Text, UniqueConstraint, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

DEFAULT_PROVIDER_URL = "https://github.com"


class Base(DeclarativeBase):
    pass


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    provider_id: Mapped[str] = mapped_column(
        Text, nullable=False, server_default=text("''")
    )
    repo: Mapped[str] = mapped_column(Text, nullable=False)
    branch_name: Mapped[str] = mapped_column(Text, nullable=False)
    git_hash: Mapped[str] = mapped_column(Text, nullable=False)
    received_ts: Mapped[int] = mapped_column(Integer, nullable=False)
    overall_percent: Mapped[float] = mapped_column(Float, nullable=False)
    report_dir: Mapped[str] = mapped_column(Text, nullable=False)
    provider_url: Mapped[str] = mapped_column(
        Text, nullable=False, server_default=text("'https://github.com'")
    )
    provider_name: Mapped[str] = mapped_column(
        Text, nullable=False, server_default=text("''")
    )

    __table_args__ = (
        UniqueConstraint(
            "provider_id", "repo", "git_hash", name="uq_reports_provider_repo_hash"
        ),
        Index(
            "idx_reports_prov_repo_branch_ts",
            "provider_id",
            "repo",
            "branch_name",
            "received_ts",
        ),
        Index(
            "idx_reports_prov_repo_hash_ts",
            "provider_id",
            "repo",
            "git_hash",
            "received_ts",
        ),
    )


class BranchHead(Base):
    __tablename__ = "branch_heads"

    provider_id: Mapped[str] = mapped_column(
        Text, primary_key=True, server_default=text("''")
    )
    repo: Mapped[str] = mapped_column(Text, primary_key=True)
    branch_name: Mapped[str] = mapped_column(Text, primary_key=True)
    current_hash: Mapped[str] = mapped_column(Text, nullable=False)
    updated_ts: Mapped[int] = mapped_column(Integer, nullable=False)

    __table_args__ = (
        Index("idx_branch_heads_prov_repo_hash", "provider_id", "repo", "current_hash"),
    )


class BranchEvent(Base):
    __tablename__ = "branch_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    provider_id: Mapped[str] = mapped_column(
        Text, nullable=False, server_default=text("''")
    )
    repo: Mapped[str] = mapped_column(Text, nullable=False)
    branch_name: Mapped[str] = mapped_column(Text, nullable=False)
    git_hash: Mapped[str] = mapped_column(Text, nullable=False)
    updated_ts: Mapped[int] = mapped_column(Integer, nullable=False)

    __table_args__ = (
        Index(
            "idx_branch_events_prov_repo_branch_ts",
            "provider_id",
            "repo",
            "branch_name",
            "updated_ts",
        ),
        Index(
            "idx_branch_events_prov_repo_hash_ts",
            "provider_id",
            "repo",
            "git_hash",
            "updated_ts",
        ),
    )


class Repo(Base):
    __tablename__ = "repos"

    provider_id: Mapped[str] = mapped_column(
        Text, primary_key=True, server_default=text("''")
    )
    repo: Mapped[str] = mapped_column(Text, primary_key=True)
    first_seen_ts: Mapped[int] = mapped_column(Integer, nullable=False)
    last_seen_ts: Mapped[int] = mapped_column(Integer, nullable=False)
