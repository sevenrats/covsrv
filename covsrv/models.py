"""SQLAlchemy ORM models for covsrv."""

from __future__ import annotations

from sqlalchemy import Float, Index, Integer, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    repo: Mapped[str] = mapped_column(Text, nullable=False)
    branch_name: Mapped[str] = mapped_column(Text, nullable=False)
    git_hash: Mapped[str] = mapped_column(Text, nullable=False)
    received_ts: Mapped[int] = mapped_column(Integer, nullable=False)
    overall_percent: Mapped[float] = mapped_column(Float, nullable=False)
    report_dir: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        UniqueConstraint("repo", "git_hash", name="uq_reports_repo_hash"),
        Index("idx_reports_repo_branch_ts", "repo", "branch_name", "received_ts"),
        Index("idx_reports_repo_hash_ts", "repo", "git_hash", "received_ts"),
    )


class BranchHead(Base):
    __tablename__ = "branch_heads"

    repo: Mapped[str] = mapped_column(Text, primary_key=True)
    branch_name: Mapped[str] = mapped_column(Text, primary_key=True)
    current_hash: Mapped[str] = mapped_column(Text, nullable=False)
    updated_ts: Mapped[int] = mapped_column(Integer, nullable=False)

    __table_args__ = (Index("idx_branch_heads_repo_hash", "repo", "current_hash"),)


class BranchEvent(Base):
    __tablename__ = "branch_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    repo: Mapped[str] = mapped_column(Text, nullable=False)
    branch_name: Mapped[str] = mapped_column(Text, nullable=False)
    git_hash: Mapped[str] = mapped_column(Text, nullable=False)
    updated_ts: Mapped[int] = mapped_column(Integer, nullable=False)

    __table_args__ = (
        Index("idx_branch_events_repo_branch_ts", "repo", "branch_name", "updated_ts"),
        Index("idx_branch_events_repo_hash_ts", "repo", "git_hash", "updated_ts"),
    )


class Repo(Base):
    __tablename__ = "repos"

    repo: Mapped[str] = mapped_column(Text, primary_key=True)
    first_seen_ts: Mapped[int] = mapped_column(Integer, nullable=False)
    last_seen_ts: Mapped[int] = mapped_column(Integer, nullable=False)
