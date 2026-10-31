
import time

import numpy as np
import pandas as pd
from huggingface_hub import hf_hub_download
from dotenv import load_dotenv

from phishing_detection.model import PhishingURLClassifier


def calculate_metrics(actual, predicted):
    tp = sum(a == 1 and p == 1 for a, p in zip(actual, predicted))
    tn = sum(a == 0 and p == 0 for a, p in zip(actual, predicted))
    fp = sum(a == 0 and p == 1 for a, p in zip(actual, predicted))
    fn = sum(a == 1 and p == 0 for a, p in zip(actual, predicted))

    accuracy = (tp + tn) / len(actual)
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0
    )

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fp": fp,
        "fn": fn,
    }


def main():
    load_dotenv()

    dataset_path = hf_hub_download(
        repo_id="pirocheto/phishing-url",
        filename="data/test.parquet",
        repo_type="dataset",
    )

    df = pd.read_parquet(dataset_path)
    df = df.dropna(subset=["url", "status"]).copy()

    df["actual"] = df["status"].map({
        "legitimate": 0,
        "phishing": 1,
    })

    df = df.dropna(subset=["actual"])
    df["actual"] = df["actual"].astype(int)

    # Deterministic stratified split: half validation, half holdout
    rng = np.random.default_rng(42)

    validation_parts = []
    holdout_parts = []

    for _, group in df.groupby("actual"):
        indices = rng.permutation(group.index.to_numpy())
        midpoint = len(indices) // 2

        validation_parts.append(df.loc[indices[:midpoint]])
        holdout_parts.append(df.loc[indices[midpoint:]])

    validation = pd.concat(validation_parts)
    holdout = pd.concat(holdout_parts)

    classifier = PhishingURLClassifier()

    def get_scores(data):
        scores = []

        for url in data["url"]:
            result = classifier.predict(str(url))
            scores.append(result["phishing_score"])

        return np.array(scores)

    print("Generating validation predictions...")
    validation_scores = get_scores(validation)

    print("Generating holdout predictions...")
    holdout_scores = get_scores(holdout)

    validation_actual = validation["actual"].to_numpy()
    holdout_actual = holdout["actual"].to_numpy()

    thresholds = [0.30, 0.40, 0.50, 0.60, 0.70]

    print("\n========== VALIDATION THRESHOLD RESULTS ==========")
    print("Threshold | Precision | Recall | F1 | FP | FN")

    results = []

    for threshold in thresholds:
        predicted = (validation_scores >= threshold).astype(int)
        metrics = calculate_metrics(validation_actual, predicted)

        results.append((threshold, metrics))

        print(
            f"{threshold:9.2f} | "
            f"{metrics['precision']:.4f} | "
            f"{metrics['recall']:.4f} | "
            f"{metrics['f1']:.4f} | "
            f"{metrics['fp']} | {metrics['fn']}"
        )

    # Select threshold using validation F1 only
    best_threshold, best_metrics = max(
        results,
        key=lambda item: item[1]["f1"],
    )

    print("\nSelected threshold:", best_threshold)

    # Evaluate selected threshold on untouched holdout half
    holdout_predicted = (
        holdout_scores >= best_threshold
    ).astype(int)

    holdout_metrics = calculate_metrics(
        holdout_actual,
        holdout_predicted,
    )

    print("\n========== FINAL HOLDOUT RESULTS ==========")
    print("Threshold:", best_threshold)

    for metric, value in holdout_metrics.items():
        print(f"{metric.upper():10}: {value:.4f}" if isinstance(value, float)
              else f"{metric.upper():10}: {value}")

    print("\nHoldout URLs:", len(holdout))
    print("===========================================")


if __name__ == "__main__":
    main()
