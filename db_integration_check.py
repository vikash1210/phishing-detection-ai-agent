
import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from phishing_detection.database import Base, engine
from phishing_detection.db_models import (
    Alert,
    ConnectedAccount,
    Email,
    ScanResult,
    ScannedURL,
    User,
)


def run_database_integration_test():
    """Verify database models, relationships, and constraints."""

    test_id = uuid.uuid4().hex
    test_email = f"db-test-{test_id}@example.invalid"

    print("\nStarting PostgreSQL integration test...")

    with engine.connect() as connection:
        outer_transaction = connection.begin()

        try:
            with Session(
                bind=connection,
                join_transaction_mode="create_savepoint",
            ) as session:

                # 1. Create application user.
                user = User(
                    email=test_email,
                    full_name="Database Integration Test",
                )
                session.add(user)
                session.flush()

                assert user.id is not None
                print("1. User creation: SUCCESS")

                # 2. Create connected Gmail account.
                account = ConnectedAccount(
                    user=user,
                    provider="google",
                    provider_account_id=f"google-{test_id}",
                    email_address=test_email,
                    scopes=["gmail.readonly"],
                    status="active",
                )
                session.add(account)
                session.flush()

                assert account.user_id == user.id
                print("2. Connected account creation: SUCCESS")

                # 3. Create email metadata.
                email = Email(
                    connected_account=account,
                    provider_message_id=f"message-{test_id}",
                    sender="sender@example.com",
                    recipient=test_email,
                    subject="Database integration test",
                    snippet="Test email metadata",
                )
                session.add(email)
                session.flush()

                assert email.connected_account_id == account.id
                print("3. Email creation: SUCCESS")

                # 4. Associate a URL with the email.
                scanned_url = ScannedURL(
                    email=email,
                    original_url="https://example.com/login",
                    normalized_url="https://example.com/login",
                    domain="example.com",
                )
                session.add(scanned_url)
                session.flush()

                assert scanned_url.email_id == email.id
                print("4. Scanned URL creation: SUCCESS")

                # 5. Save AI scan result.
                scan_result = ScanResult(
                    scanned_url=scanned_url,
                    model_label=1,
                    prediction="phishing",
                    phishing_score=0.98,
                    threat_status="not_checked",
                    threat_match=False,
                    risk_level="high",
                    verification_status="test",
                    evidence=[{"source": "integration_test"}],
                    reasons=["Test scan result"],
                    agent_version="integration-test",
                )
                session.add(scan_result)
                session.flush()

                assert scan_result.scanned_url_id == scanned_url.id
                print("5. Scan result creation: SUCCESS")

                # 6. Create a security alert.
                alert = Alert(
                    user=user,
                    email_id=email.id,
                    scan_result=scan_result,
                    alert_type="phishing_detected",
                    severity="high",
                    title="Test phishing alert",
                    message="Integration test alert",
                )
                session.add(alert)
                session.flush()

                assert alert.user_id == user.id
                assert alert.scan_result_id == scan_result.id
                print("6. Security alert creation: SUCCESS")

                # 7. Verify relationships and stored records.
                assert session.scalar(
                    select(func.count()).select_from(User).where(
                        User.id == user.id
                    )
                ) == 1

                assert session.scalar(
                    select(func.count()).select_from(ConnectedAccount).where(
                        ConnectedAccount.user_id == user.id
                    )
                ) == 1

                assert session.scalar(
                    select(func.count()).select_from(Email).where(
                        Email.connected_account_id == account.id
                    )
                ) == 1

                assert session.scalar(
                    select(func.count()).select_from(ScannedURL).where(
                        ScannedURL.email_id == email.id
                    )
                ) == 1

                assert session.scalar(
                    select(func.count()).select_from(ScanResult).where(
                        ScanResult.scanned_url_id == scanned_url.id
                    )
                ) == 1

                assert session.scalar(
                    select(func.count()).select_from(Alert).where(
                        Alert.user_id == user.id
                    )
                ) == 1

                print("7. Database relationships: SUCCESS")

                # 8. Verify unique email constraint.
                duplicate_rejected = False

                try:
                    with session.begin_nested():
                        duplicate_user = User(
                            email=test_email,
                            full_name="Duplicate Test User",
                        )
                        session.add(duplicate_user)
                        session.flush()

                except IntegrityError:
                    duplicate_rejected = True

                assert duplicate_rejected, (
                    "Database allowed a duplicate user email!"
                )

                print("8. Unique constraint enforcement: SUCCESS")

                # Verify all six model tables are registered.
                assert len(Base.metadata.tables) == 6
                print("9. Six database models registered: SUCCESS")

            # Roll back the outer transaction so test records are removed.
            outer_transaction.rollback()

            print("\nAll integration checks passed!")
            print("Test records rolled back successfully.")

        except Exception:
            if outer_transaction.is_active:
                outer_transaction.rollback()
            raise


if __name__ == "__main__":
    run_database_integration_test()
