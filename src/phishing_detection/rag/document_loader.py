
from pathlib import Path
import re


def load_documents(knowledge_base_dir: str | Path) -> list[dict[str, str]]:
    """Load non-empty text documents from a knowledge-base directory."""
    directory = Path(knowledge_base_dir)

    if not directory.exists():
        raise FileNotFoundError(
            f"Knowledge-base directory not found: {directory}"
        )

    if not directory.is_dir():
        raise NotADirectoryError(
            f"Knowledge-base path is not a directory: {directory}"
        )

    documents = []

    for file_path in sorted(directory.glob("*.txt")):
        text = file_path.read_text(encoding="utf-8").strip()

        if text:
            documents.append(
                {
                    "text": text,
                    "source": file_path.name,
                }
            )

    return documents


def split_into_chunks(
    text: str,
    chunk_size: int = 500,
    overlap: int = 50,
) -> list[str]:
    """
    Split security documents by guideline headings where possible.
    Fall back to overlapping character chunks for other documents.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero.")

    if overlap < 0 or overlap >= chunk_size:
        raise ValueError(
            "overlap must be non-negative and smaller than chunk_size."
        )

    text = text.strip()

    if not text:
        return []

    # Detect headings such as "Guideline 1: Inspect the hostname."
    heading_pattern = re.compile(
        r"(?m)^Guideline\s+\d+\s*:"
    )
    matches = list(heading_pattern.finditer(text))

    if matches:
        prefix = text[:matches[0].start()].strip()
        chunks = []

        if prefix:
            chunks.append(prefix)

        for index, match in enumerate(matches):
            start = match.start()
            end = (
                matches[index + 1].start()
                if index + 1 < len(matches)
                else len(text)
            )

            guideline_text = text[start:end].strip()

            if guideline_text:
                chunks.append(guideline_text)

        return chunks

    # Fallback for documents without guideline headings.
    chunks = []
    start = 0

    while start < len(text):
        end = min(start + chunk_size, len(text))
        chunk = text[start:end].strip()

        if chunk:
            chunks.append(chunk)

        if end == len(text):
            break

        start = end - overlap

    return chunks
