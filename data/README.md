# Dataset acquisition and format

## Selected data strategy

Use a reproducibly assembled raw-URL dataset rather than a dataset that contains
precomputed features:

- **Phishing examples:** a dated snapshot of the PhishTank verified phishing
  feed.
- **Legitimate examples:** a dated snapshot of the Tranco ranked-domain list,
  expanded into HTTP and HTTPS homepage URLs.

This combination keeps the model input at the URL level and makes source and
collection dates explicit. It is not a guarantee that the sources are unbiased
or representative of future traffic. Before distributing or using a dataset,
confirm each source's current terms, attribution requirements, and permitted
use. Record the source URLs, retrieval timestamps, transformations, and file
hashes alongside the dataset. Remove exact duplicate URLs and avoid placing
personal or otherwise sensitive URLs in a public repository.

No third-party dataset is downloaded or included by this project. Fetching,
merging, and source-specific licensing checks are intentionally outside this
validation step.

## CSV contract

Provide a UTF-8 CSV with exactly these columns:

| Column | Required values |
| --- | --- |
| `url` | A non-empty absolute `http://` or `https://` URL with a valid hostname and optional valid port |
| `label` | `phishing`/`malicious`/`1` or `legitimate`/`benign`/`0` |

Whitespace around values is ignored. The validator emits normalized labels as
integers (`0` for legitimate, `1` for phishing). URL validation rejects missing
hostnames, malformed authorities, invalid or empty ports, invalid IP literals,
and hostnames that do not conform to DNS label syntax. Additional columns,
empty datasets, missing values, unsupported labels, malformed URLs, and
duplicate URLs are rejected with row-specific diagnostics where applicable.

Example format only (not a dataset or training sample):

```csv
url,label
https://example.invalid/,legitimate
https://login.example.invalid/verify,phishing
```

## Validate a dataset

From the project root, install the project and run:

```powershell
python -m pip install -e ".[dev]"
python tools/validate_dataset.py path\to\input.csv --output path\to\validated.csv
```

The output is written only after the entire input passes validation. Choose a
separate output path; the tool refuses to overwrite the input file.
