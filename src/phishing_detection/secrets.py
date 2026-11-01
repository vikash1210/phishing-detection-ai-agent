
import keyring

SERVICE_NAME = "PhishingDetectionAI"


def get_secret(name: str) -> str:
    """
    Retrieve a secret from Windows Credential Manager.
    """
    value = keyring.get_password(SERVICE_NAME, name)

    if not value:
        raise RuntimeError(
            f"Required secret '{name}' was not found "
            "in Windows Credential Manager."
        )

    return value
