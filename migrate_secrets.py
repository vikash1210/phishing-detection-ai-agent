
import os
from pathlib import Path

import keyring
from dotenv import dotenv_values

ENV_FILE = Path(".env")

SECRET_NAMES = [
    "GROQ_API_KEY",
    "GOOGLE_SAFE_BROWSING_API_KEY",
    "GMAIL_ADDON_API_KEY",
]
def main():
    if not ENV_FILE.exists():
        print(".env file not found.")
        return

    secrets = dotenv_values(ENV_FILE)
    saved = []

    for name in SECRET_NAMES:
        value = secrets.get(name)

        if value:
            keyring.set_password(
                "PhishingDetectionAI",
                name,
                value
            )
            saved.append(name)

    print("Secrets saved to Windows Credential Manager:")
    for name in saved:
        print(f" - {name}")

    print(f"Total saved: {len(saved)}")
    print("Secret values were not displayed.")

if __name__ == "__main__":
    main()
