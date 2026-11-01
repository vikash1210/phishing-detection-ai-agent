
from googleapiclient.discovery import build

from phishing_detection.gmail_auth import authenticate_gmail


def list_recent_emails(max_results=5):
    credentials = authenticate_gmail()

    service = build("gmail", "v1", credentials=credentials)

    response = service.users().messages().list(
        userId="me",
        maxResults=max_results
    ).execute()

    messages = response.get("messages", [])

    for message in messages:
        details = service.users().messages().get(
            userId="me",
            id=message["id"],
            format="metadata",
            metadataHeaders=["Subject", "From", "Date"]
        ).execute()

        headers = details.get("payload", {}).get("headers", [])
        email_info = {
            header["name"]: header["value"]
            for header in headers
        }

        print("-" * 50)
        print("Message ID:", message["id"])
        print("From:", email_info.get("From", "Unknown"))
        print("Subject:", email_info.get("Subject", "No Subject"))
        print("Date:", email_info.get("Date", "Unknown"))


if __name__ == "__main__":
    list_recent_emails()
