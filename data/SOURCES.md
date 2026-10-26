# Dataset Source Registry



## Purpose



This document records dataset provenance, licensing checks, and inclusion decisions before any third-party data is downloaded or used for model training.



## Source 1: PhishTank



- **Purpose:** Candidate source for verified phishing URLs.

- **Official developer documentation:** https://www.phishtank.org/developer_info.php

- **Terms reference:** https://phishtank.org/terms.php

- **Current terms reviewed:** Pending confirmation.

- **Retrieval date:** Not downloaded.

- **License and attribution status:** Not yet approved for inclusion.

- **Decision:** Do not download or redistribute data until applicable terms and access requirements are confirmed.



## Source 2: Tranco



- **Purpose:** Candidate source for popular legitimate domains.

- **Official website:** https://tranco-list.eu/

- **List identifier:** Not selected.

- **Retrieval date:** Not downloaded.

- **License and attribution status:** Verify the selected list configuration and applicable terms.

- **Decision:** Do not include a list in the training dataset until its intended use and licensing restrictions are reviewed.



## Dataset Inclusion Requirements



Before a source is approved, record:



- Source name and official URL.

- Applicable terms and license information.

- Intended use and redistribution restrictions.

- Retrieval timestamp and dataset snapshot identifier.

- Original file SHA-256 hash.

- Transformation steps and final dataset hash.

- Label definitions and known limitations.



## Safety and Reproducibility



- Keep raw source files separate from processed datasets.

- Never commit API keys, credentials, or private data.

- Do not silently discard invalid records.

- Preserve source attribution and applicable notices.

- Do not claim that a dataset is licensed for commercial use without supporting evidence.



No third-party dataset has been downloaded or approved by this registry yet.


