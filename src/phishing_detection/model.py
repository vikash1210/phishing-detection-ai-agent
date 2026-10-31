
import os
from urllib.parse import urlparse

import numpy as np
import onnxruntime as ort
from huggingface_hub import hf_hub_download


class PhishingURLClassifier:
    """Run phishing URL predictions with a pretrained ONNX model."""

    def __init__(self):
        try:
            self.threshold = float(
                os.getenv("PHISHING_THRESHOLD", "0.50")
            )
        except ValueError as exc:
            raise ValueError(
                "PHISHING_THRESHOLD must be a number between 0 and 1."
            ) from exc

        if not 0.0 <= self.threshold <= 1.0:
            raise ValueError(
                "PHISHING_THRESHOLD must be between 0 and 1."
            )

        model_path = hf_hub_download(
            repo_id="pirocheto/phishing-url-detection",
            filename="model.onnx",
        )

        self.session = ort.InferenceSession(
            model_path,
            providers=["CPUExecutionProvider"],
        )

        output_names = [
            item.name for item in self.session.get_outputs()
        ]

        if "label" not in output_names or "probabilities" not in output_names:
            raise RuntimeError("Unexpected ONNX model output schema.")

        self.input_name = self.session.get_inputs()[0].name

    def predict(self, url: str) -> dict:
        """Return the predicted class and phishing score for one URL."""

        if not isinstance(url, str) or not url.strip():
            raise ValueError("URL must be a non-empty string.")

        clean_url = url.strip()
        parsed = urlparse(clean_url)

        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("URL must be a valid HTTP or HTTPS URL.")

        outputs = self.session.run(
            None,
            {
                self.input_name: np.array(
                    [clean_url],
                    dtype=str,
                )
            },
        )

        output_names = [
            item.name for item in self.session.get_outputs()
        ]

        result = dict(zip(output_names, outputs))

        probabilities = result["probabilities"][0]

        if len(probabilities) != 2:
            raise RuntimeError("Unexpected model prediction format.")

        phishing_score = float(probabilities[1])

        # Apply the configurable phishing threshold.
        label = 1 if phishing_score >= self.threshold else 0

        return {
            "url": clean_url,
            "label": label,
            "prediction": "phishing" if label == 1 else "legitimate",
            "phishing_score": round(phishing_score, 6),
        }
