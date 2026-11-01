
from pathlib import Path
import sys
from datetime import datetime

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)

# Project root and source package path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from phishing_detection.model import PhishingURLClassifier


def main():
    dataset_path = PROJECT_ROOT / "data" / "raw" / "phiusiil_original.csv"
    reports_dir = PROJECT_ROOT / "reports"
    reports_dir.mkdir(exist_ok=True)

    print("Loading dataset...")

    df = pd.read_csv(
        dataset_path,
        usecols=["URL", "label"],
    )

    # Remove duplicate URLs; previous check confirmed
    # that duplicate URLs have no conflicting labels.
    df = df.drop_duplicates(subset=["URL"]).copy()

    # UCI original mapping:
    # 0 = phishing, 1 = legitimate
    # Project mapping:
    # 0 = legitimate, 1 = phishing
    df["target"] = 1 - df["label"].astype(int)

    # Select 1,000 URLs from each class
    sample_parts = []

    for class_label in [0, 1]:
        class_data = df[df["target"] == class_label]

        sample_parts.append(
            class_data.sample(
                n=1000,
                random_state=42,
            )
        )

    evaluation_df = pd.concat(
        sample_parts
    ).sample(
        frac=1,
        random_state=42,
    ).reset_index(drop=True)

    y_true = evaluation_df["target"].tolist()

    print("Evaluation sample:", len(evaluation_df))
    print("Loading existing ONNX model...")

    classifier = PhishingURLClassifier()

    y_pred = []
    prediction_rows = []

    for index, row in evaluation_df.iterrows():
        result = classifier.predict(row["URL"])

        prediction = int(result["label"])
        y_pred.append(prediction)

        prediction_rows.append({
            "url": result["url"],
            "actual_label": int(row["target"]),
            "predicted_label": prediction,
            "prediction": result["prediction"],
            "phishing_score": result["phishing_score"],
        })

        if (index + 1) % 100 == 0:
            print(f"Processed {index + 1}/2000 URLs")

    # Calculate evaluation metrics
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(
        y_true, y_pred, pos_label=1, zero_division=0
    )
    recall = recall_score(
        y_true, y_pred, pos_label=1, zero_division=0
    )
    f1 = f1_score(
        y_true, y_pred, pos_label=1, zero_division=0
    )

    matrix = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1],
    )

    report = classification_report(
        y_true,
        y_pred,
        labels=[0, 1],
        target_names=["Legitimate", "Phishing"],
        zero_division=0,
    )

    tn, fp, fn, tp = matrix.ravel()

    # Prepare evaluation report
    report_text = f"""
PHISHING DETECTION MODEL EVALUATION
===================================

Evaluation date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Model: pirocheto/phishing-url-detection (ONNX)
Threshold: {classifier.threshold}
Dataset: UCI PhiUSIIL
Evaluation method: Stratified sample
Sample size: {len(evaluation_df)}
Class distribution: 1000 Legitimate, 1000 Phishing

METRICS
-------

Accuracy:  {accuracy:.4f}
Precision: {precision:.4f}
Recall:    {recall:.4f}
F1-score:  {f1:.4f}

CONFUSION MATRIX
----------------

                 Predicted
                 Legit  Phish

Actual Legit     {tn:5d}  {fp:5d}
Actual Phish     {fn:5d}  {tp:5d}

Classification Report
---------------------

{report}

NOTE:
This is a 2,000-URL sample evaluation.
Results may be affected by dataset and model
distribution differences. They do not guarantee
real-world production performance.
"""

    report_path = reports_dir / "model_evaluation.txt"
    report_path.write_text(report_text, encoding="utf-8")

    predictions_path = (
        reports_dir / "model_evaluation_predictions.csv"
    )

    pd.DataFrame(prediction_rows).to_csv(
        predictions_path,
        index=False,
    )

    print(report_text)
    print("Report saved:", report_path)
    print("Predictions saved:", predictions_path)


if __name__ == "__main__":
    main()
