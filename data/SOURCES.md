# Dataset Source Registry

## Purpose

This document records dataset provenance, licensing checks, and inclusion decisions before any third-party data is downloaded or used for model training.

## Source 1: PhishTank

- Purpose: Candidate source for verified phishing URLs.
- Official developer documentation: https://www.phishtank.org/developer_info.php
- Terms reference: https://phishtank.org/terms.php
- Current terms reviewed: Pending confirmation.
- Retrieval date: Not downloaded.
- License and attribution status: Not yet approved for inclusion.
- Decision: Do not download or redistribute data until applicable terms and access requirements are confirmed.

## Source 2: Tranco

- Purpose: Candidate source for popular legitimate domains.
- Official website: https://tranco-list.eu/
- List identifier: Not selected.
- Retrieval date: Not downloaded.
- License and attribution status: Verify the selected list configuration and applicable terms.
- Decision: Do not include a list in the training dataset until its intended use and licensing restrictions are reviewed.

## Source 3: UCI PhiUSIIL Phishing URL Dataset

- Purpose: Candidate source for URL-level phishing classification.
- Official source: https://archive.ics.uci.edu/dataset/967/phiusil-phishing-url-dataset
- Published license: CC BY 4.0; intended use and attribution requirements still require review.
- Retrieval date: Not downloaded.
- Label mapping: Source label 1 = legitimate; source label 0 = phishing. Verify against official documentation before transforming.
- Planned transformation: Convert labels to the project convention: 0 = legitimate, 1 = phishing.
- Limitations: The dataset includes precomputed website features. These will not automatically be used in the URL-only baseline.
- Decision: Candidate only. Verify schema, labels, attribution, and intended-use requirements before download or training.

## Dataset Inclusion Requirements

Before a source is approved, record:

1. Source name and official URL.
2. Applicable terms and license information.
3. Intended use and redistribution restrictions.
4. Retrieval timestamp and dataset snapshot identifier.
5. Original file SHA-256 hash.
6. Transformation steps and final dataset hash.
7. Label definitions and known limitations.
8. Approval decision and supporting evidence.

## Safety and Reproducibility

- Keep raw source files separate from processed datasets.
- Never commit API keys, credentials, or private data.
- Do not silently discard invalid records.
- Preserve source attribution and applicable notices.
- Do not claim that a dataset is licensed for commercial use without supporting evidence.
- Keep dataset snapshots reproducible and record all transformations.

## Current Status

No third-party dataset has been downloaded or approved by this registry yet. PhishTank, Tranco, and UCI PhiUSIIL remain candidate sources pending confirmation of applicable terms and intended-use requirements.
