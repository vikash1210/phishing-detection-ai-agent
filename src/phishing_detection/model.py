
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
import onnxruntime as ort
from huggingface_hub import hf_hub_download


class PhishingURLClassifier:
    """Run phishing URL predictions with a pretrained ONNX model."""

    def __init__(self):
        model_path = hf_hub_download(
            repo_id="pirocheto/phishing-url-detection",
            filename="model.onnx",
        )
        self.session = ort.InferenceSession(
            model_path,
            providers=["CPUExecutionProvider"],
        )

        output_names = [item.name for item in self.session.get_outputs()]
        if "label" not in output_names or "probabilities" not in output_names:
            raise RuntimeError("Unexpected ONNX model output schema.")

        self.input_name = self.session.get_inputs()[0].name

    def predict(self, url: str) -> dict:
        """Return the predicted class and phishing score for one URL."""
        if not isinstance(url, str) or not url.strip():
            raise ValueError("URL must be a non-empty string.")

        parsed = urlparse(url.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("URL must be a valid HTTP or HTTPS URL.")

        outputs = self.session.run(
            None,
            {self.input_name: np.array([url.strip()], dtype=str)},
        )
        output_names = [item.name for item in self.session.get_outputs()]
        result = dict(zip(output_names, outputs))

        label = int(result["label"][0])
        probabilities = result["probabilities"][0]

        if label not in (0, 1) or len(probabilities) != 2:
            raise RuntimeError("Unexpected model prediction format.")

        return {
            "url": url.strip(),
            "label": label,
            "prediction": "phishing" if label == 1 else "legitimate",
            "phishing_score": round(float(probabilities[1]), 6),
        }
