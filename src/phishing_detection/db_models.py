
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    JSON,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from phishing_detection.database import Base


def utc_now() -> datetime:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc)


class User(Base):
    """Application user account."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(
        String(320), unique=True, nullable=False, index=True
    )
    full_name: Mapped[str | None] = mapped_column(String(200))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )

    connected_accounts: Mapped[list["ConnectedAccount"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    alerts: Mapped[list["Alert"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class ConnectedAccount(Base):
    """External email account connected through OAuth."""

    __tablename__ = "connected_accounts"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider: Mapped[str] = mapped_column(String(30), nullable=False)
    provider_account_id: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    email_address: Mapped[str] = mapped_column(String(320), nullable=False)
    access_token_encrypted: Mapped[str | None] = mapped_column(Text)
    refresh_token_encrypted: Mapped[str | None] = mapped_column(Text)
    token_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    scopes: Mapped[list | None] = mapped_column(JSON)
    history_id: Mapped[str | None] = mapped_column(String(255))
    watch_expiration: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    status: Mapped[str] = mapped_column(
        String(30), default="active", nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint(
            "provider",
            "provider_account_id",
            name="uq_connected_account_provider_id",
        ),
    )

    user: Mapped["User"] = relationship(back_populates="connected_accounts")
    emails: Mapped[list["Email"]] = relationship(
        back_populates="connected_account",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class Email(Base):
    """Email metadata received from a connected account."""

    __tablename__ = "emails"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    connected_account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("connected_accounts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider_message_id: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    thread_id: Mapped[str | None] = mapped_column(String(255))
    sender: Mapped[str | None] = mapped_column(String(320))
    recipient: Mapped[str | None] = mapped_column(String(320))
    subject: Mapped[str | None] = mapped_column(String(998))
    snippet: Mapped[str | None] = mapped_column(Text)
    received_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    status: Mapped[str] = mapped_column(
        String(30), default="received", nullable=False
    )
    message_hash: Mapped[str | None] = mapped_column(String(128))
    processed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    __table_args__ = (
        UniqueConstraint(
            "connected_account_id",
            "provider_message_id",
            name="uq_email_account_provider_message",
        ),
        Index("ix_emails_received_at", "received_at"),
    )

    connected_account: Mapped["ConnectedAccount"] = relationship(
        back_populates="emails"
    )
    scanned_urls: Mapped[list["ScannedURL"]] = relationship(
        back_populates="email",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class ScannedURL(Base):
    """URL extracted from an email or submitted manually."""

    __tablename__ = "scanned_urls"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("emails.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    original_url: Mapped[str] = mapped_column(
        String(4096), nullable=False
    )
    normalized_url: Mapped[str] = mapped_column(
        String(4096), nullable=False
    )
    domain: Mapped[str | None] = mapped_column(String(255), index=True)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    __table_args__ = (
        UniqueConstraint(
            "email_id",
            "normalized_url",
            name="uq_scanned_url_email_normalized",
        ),
    )

    email: Mapped["Email | None"] = relationship(
        back_populates="scanned_urls"
    )
    scan_results: Mapped[list["ScanResult"]] = relationship(
        back_populates="scanned_url",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class ScanResult(Base):
    """Stores an individual AI phishing scan result."""

    __tablename__ = "scan_results"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scanned_url_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scanned_urls.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    model_label: Mapped[int | None] = mapped_column()
    prediction: Mapped[str] = mapped_column(
        String(50), nullable=False
    )
    phishing_score: Mapped[float | None] = mapped_column(Float)
    threat_status: Mapped[str | None] = mapped_column(String(50))
    threat_match: Mapped[bool | None] = mapped_column(Boolean)
    risk_level: Mapped[str | None] = mapped_column(String(30))
    verification_status: Mapped[str | None] = mapped_column(String(50))
    evidence: Mapped[list | None] = mapped_column(JSON)
    reasons: Mapped[list | None] = mapped_column(JSON)
    agent_version: Mapped[str | None] = mapped_column(String(100))
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    scanned_url: Mapped["ScannedURL"] = relationship(
        back_populates="scan_results"
    )
    alerts: Mapped[list["Alert"]] = relationship(
        back_populates="scan_result",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class Alert(Base):
    """Security alert generated from a phishing scan."""

    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    email_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("emails.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    scan_result_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scan_results.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    alert_type: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(30), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(
        String(30), default="unread", nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    read_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )

    __table_args__ = (
        UniqueConstraint(
            "scan_result_id",
            "alert_type",
            name="uq_alert_scan_result_type",
        ),
    )

    user: Mapped["User"] = relationship(back_populates="alerts")
    scan_result: Mapped["ScanResult"] = relationship(
        back_populates="alerts"
    )
