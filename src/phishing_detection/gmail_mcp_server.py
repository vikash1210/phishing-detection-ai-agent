
import base64
import re
from html.parser import HTMLParser
from phishing_detection.agent.graph import build_phishing_graph
from phishing_detection.model import PhishingURLClassifier
from phishing_detection.rag.retriever import SemanticRetriever
from phishing_detection.risk_assessment import assess_risk
from googleapiclient.discovery import build
from mcp.server.mcpserver import MCPServer

from phishing_detection.gmail_auth import authenticate_gmail


mcp = MCPServer("Gmail Phishing Detection")
# --------------------------------------------------
# Phishing Detection Initialization
# --------------------------------------------------

classifier = PhishingURLClassifier()
retriever = SemanticRetriever()

graph = build_phishing_graph(classifier, retriever)


# --------------------------------------------------
# Gmail Service
# --------------------------------------------------

def get_gmail_service():
    """Create an authenticated Gmail API service."""

    credentials = authenticate_gmail()

    return build(
        "gmail",
        "v1",
        credentials=credentials
    )


# --------------------------------------------------
# Email Body Decoding
# --------------------------------------------------

def decode_email_body(data: str) -> str:
    """Decode Gmail URL-safe Base64 email content."""

    if not data:
        return ""

    padding = "=" * (-len(data) % 4)

    decoded = base64.urlsafe_b64decode(data + padding)

    return decoded.decode(
        "utf-8",
        errors="replace"
    )


def collect_email_content(payload: dict) -> tuple[str, str]:
    """
    Recursively collect plain-text and HTML content
    from Gmail MIME payload.
    """

    plain_text = []
    html_content = []

    mime_type = payload.get("mimeType", "")
    body_data = payload.get("body", {}).get("data")

    if body_data:
        content = decode_email_body(body_data)

        if mime_type == "text/plain":
            plain_text.append(content)

        elif mime_type == "text/html":
            html_content.append(content)

    for part in payload.get("parts", []):
        plain, html = collect_email_content(part)

        if plain:
            plain_text.append(plain)

        if html:
            html_content.append(html)

    return (
        "\n".join(plain_text),
        "\n".join(html_content)
    )


# --------------------------------------------------
# HTML Link Extraction
# --------------------------------------------------

class EmailLinkParser(HTMLParser):
    """Extract HTTP and HTTPS links from email HTML."""

    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):

        if tag.lower() == "a":

            attributes = dict(attrs)

            href = attributes.get("href")

            if href and href.lower().startswith(
                ("http://", "https://")
            ):
                self.links.append(href)


# --------------------------------------------------
# Gmail Message Helper
# --------------------------------------------------

def get_gmail_message(message_id: str) -> dict:
    """Fetch one Gmail message."""

    if not message_id or not message_id.strip():
        raise ValueError("message_id is required")

    service = get_gmail_service()

    message = (
        service.users()
        .messages()
        .get(
            userId="me",
            id=message_id,
            format="full"
        )
        .execute()
    )

    return message


def get_email_headers(message: dict) -> dict:
    """Extract email headers."""

    headers = (
        message.get("payload", {})
        .get("headers", [])
    )

    return {
        header["name"].lower(): header["value"]
        for header in headers
    }


# --------------------------------------------------
# TOOL 1: List Emails
# --------------------------------------------------

@mcp.tool()
def list_emails(max_results: int = 10) -> list[dict]:
    """
    List recent Gmail messages.

    Returns message ID, sender, subject and date.
    """

    if not 1 <= max_results <= 20:
        raise ValueError(
            "max_results must be between 1 and 20"
        )

    service = get_gmail_service()

    response = (
        service.users()
        .messages()
        .list(
            userId="me",
            maxResults=max_results
        )
        .execute()
    )

    results = []

    for message in response.get("messages", []):

        details = (
            service.users()
            .messages()
            .get(
                userId="me",
                id=message["id"],
                format="metadata",
                metadataHeaders=[
                    "Subject",
                    "From",
                    "Date"
                ]
            )
            .execute()
        )

        headers = get_email_headers(details)

        results.append({
            "message_id": message["id"],
            "from": headers.get("from", ""),
            "subject": headers.get("subject", ""),
            "date": headers.get("date", "")
        })

    return results


# --------------------------------------------------
# TOOL 2: Get Selected Email
# --------------------------------------------------

@mcp.tool()
def get_email(message_id: str) -> dict:
    """
    Read the content of one selected Gmail message.
    """

    message = get_gmail_message(message_id)

    headers = get_email_headers(message)

    plain_text, html_content = collect_email_content(
        message.get("payload", {})
    )

    body = plain_text or html_content

    if not body:
        body = message.get("snippet", "")

    return {
        "message_id": message_id,
        "from": headers.get("from", ""),
        "subject": headers.get("subject", ""),
        "date": headers.get("date", ""),
        "body": body
    }


# --------------------------------------------------
# TOOL 3: Extract URLs
# --------------------------------------------------

@mcp.tool()
def extract_urls(message_id: str) -> list[str]:
    """
    Extract unique HTTP and HTTPS URLs from
    a selected Gmail message.

    Checks both plain-text URLs and HTML links.
    """

    message = get_gmail_message(message_id)

    plain_text, html_content = collect_email_content(
        message.get("payload", {})
    )

    extracted_urls = []

    # Extract URLs from plain-text content
    text_urls = re.findall(
        r"""https?://[^\s<>"']+""",
        plain_text,
        flags=re.IGNORECASE
    )

    extracted_urls.extend(text_urls)

    # Extract clickable links from HTML content
    if html_content:

        parser = EmailLinkParser()

        parser.feed(html_content)

        extracted_urls.extend(parser.links)

        # Also capture URLs written directly in HTML text
        html_urls = re.findall(
            r"""https?://[^\s<>"']+""",
            html_content,
            flags=re.IGNORECASE
        )

        extracted_urls.extend(html_urls)

    # Clean and remove duplicates
    cleaned_urls = []

    for url in extracted_urls:

        url = url.strip().rstrip(
            ".,;:!?)]}"
        )

        if (
            url.startswith(("http://", "https://"))
            and url not in cleaned_urls
        ):
            cleaned_urls.append(url)

    return cleaned_urls

# --------------------------------------------------
# TOOL 4: Scan Selected Email
# --------------------------------------------------

@mcp.tool()
def scan_email(message_id: str) -> dict:
    """
    Scan URLs from one selected Gmail email
    using the existing LangGraph phishing workflow.
    """

    # Read the selected email
    email = get_email(message_id)

    # Extract URLs from the selected email
    urls = extract_urls(message_id)

    scan_results = []

    for url in urls:
        try:
            # Run the existing phishing detection graph
            result = graph.invoke({"url": url})

            if result.get("error"):
                scan_results.append({
                    "url": url,
                    "status": "failed",
                    "error": result["error"],
                })
                continue

            prediction = result["prediction"]

            threat_intelligence = result.get(
                "threat_intelligence",
                {
                    "status": "unavailable",
                    "is_threat": None,
                    "matches": [],
                    "message": "Threat intelligence was not returned.",
                },
            )

            # Calculate risk using existing risk assessment logic
            risk_assessment = assess_risk(
                prediction=prediction,
                threat_intelligence=threat_intelligence,
            )

            scan_results.append({
                "url": url,
                "status": "scanned",
                "normalized_url": result.get("normalized_url"),
                "prediction": prediction,
                "threat_intelligence": threat_intelligence,
                "risk_assessment": risk_assessment,
                "evidence": result.get("evidence", []),
            })

        except Exception as exc:
            scan_results.append({
                "url": url,
                "status": "failed",
                "error": str(exc),
            })

    return {
        "message_id": message_id,
        "from": email["from"],
        "subject": email["subject"],
        "total_urls_found": len(urls),
        "total_urls_scanned": sum(
            1 for item in scan_results
            if item["status"] == "scanned"
        ),
        "results": scan_results,
    }
# --------------------------------------------------
# Start MCP Server
# --------------------------------------------------

if __name__ == "__main__":
    mcp.run()
