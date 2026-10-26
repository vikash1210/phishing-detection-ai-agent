# \# Dataset Source Registry

#

# \## Purpose

#

# This document records dataset provenance, licensing checks, and inclusion decisions before any third-party data is downloaded or used for model training.

#

# \## Source 1: PhishTank

#

# \- \*\*Purpose:\*\* Candidate source for verified phishing URLs.

# \- \*\*Official developer documentation:\*\* https://www.phishtank.org/developer\_info.php

# \- \*\*Terms reference:\*\* https://phishtank.org/terms.php

# \- \*\*Current terms reviewed:\*\* Initial review completed; intended-use requirements still need confirmation.

# \- \*\*Retrieval date:\*\* Not downloaded.

# \- \*\*License and attribution status:\*\* Pending approval.

# \- \*\*Decision:\*\* Do not download or redistribute data until applicable terms, access requirements, attribution, and intended-use restrictions are confirmed.

#

# \## Source 2: Tranco

#

# \- \*\*Purpose:\*\* Candidate source for popular legitimate domains.

# \- \*\*Official website:\*\* https://tranco-list.eu/

# \- \*\*List identifier:\*\* Not selected.

# \- \*\*Retrieval date:\*\* Not downloaded.

# \- \*\*License and attribution status:\*\* Pending review of the selected list, its configuration, and applicable terms.

# \- \*\*Decision:\*\* Do not include a list in the training dataset until its intended use, licensing restrictions, and attribution requirements are reviewed.

#

# \## Dataset Inclusion Requirements

#

# Before a source is approved, record:

#

# 1\. Source name and official URL.

# 2\. Applicable terms and license information.

# 3\. Intended use and redistribution restrictions.

# 4\. Retrieval timestamp and dataset snapshot identifier.

# 5\. Original file SHA-256 hash.

# 6\. Transformation steps and final dataset hash.

# 7\. Label definitions and known limitations.

# 8\. Approval decision and supporting evidence.

#

# \## Safety and Reproducibility

#

# \- Keep raw source files separate from processed datasets.

# \- Never commit API keys, credentials, or private data.

# \- Do not silently discard invalid records.

# \- Preserve source attribution and applicable notices.

# \- Do not claim that a dataset is licensed for commercial use without supporting evidence.

# \- Keep dataset snapshots reproducible and record all transformations.

#

# \## Current Status

#

# No third-party dataset has been downloaded or approved by this registry yet. PhishTank and Tranco remain candidate sources pending confirmation of applicable terms and intended-use requirements.

#

