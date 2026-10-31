
import time

import pandas as pd
from dotenv import load_dotenv
from huggingface_hub import hf_hub_download

from phishing_detection.model import PhishingURLClassifier


def main():
    load_dotenv()

    dataset_path = hf_hub_download(
        repo_id="pirocheto/phishing-url",
        filename="data/test.parquet",
        repo_type="dataset",
    )

    df = pd.read_parquet(dataset_path)
    df = df.dropna(subset=["url", "status"]).copy()

    classifier = PhishingURLClassifier()

    records = []
    errors = 0

    start = time.perf_counter()

    for row in df.itertuples(index=False):
        try:
            result = classifier.predict(str(row.url))

            actual = 1 if row.status == "phishing" else 0
            predicted = result["label"]

            records.append({
                "url": row.url,
                "actual": row.status,
                "predicted": result["prediction"],
                "phishing_score": result["phishing_score"],
                "error_type": (
                    "FALSE_NEGATIVE" if actual == 1 and predicted == 0
                    else "FALSE_POSITIVE" if actual == 0 and predicted == 1
                    else "CORRECT"
                ),
            })

        except Exception as exc:
            errors += 1
            print(f"Prediction error: {exc}")

    elapsed = time.perf_counter() - start

    results = pd.DataFrame(records)

    # Save only incorrect predictions
    incorrect = results[
        results["error_type"] != "CORRECT"
    ].copy()

    incorrect.to_csv(
        "evaluation_errors.csv",
        index=False,
        encoding="utf-8-sig",
    )

    print("\n========== ERROR ANALYSIS ==========")
    print("Total predictions:", len(results))
    print("Failed predictions:", errors)
    print("Correct predictions:",
          (results["error_type"] == "CORRECT").sum())

    print("\nError distribution:")
    print(results["error_type"].value_counts())

    print("\nExecution time:", round(elapsed, 2), "seconds")
    print("Error report saved: evaluation_errors.csv")
    print("====================================")


if __name__ == "__main__":
    main()
