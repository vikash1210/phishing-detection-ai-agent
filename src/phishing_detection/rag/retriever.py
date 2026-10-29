
from pathlib import Path

import numpy as np

from phishing_detection.rag.document_loader import (
    load_documents,
    split_into_chunks,
)
from phishing_detection.rag.embedding_service import EmbeddingService


class SemanticRetriever:
    """Retrieve relevant knowledge-base chunks using semantic similarity."""

    def __init__(
        self,
        knowledge_base_dir: str | Path = "data/knowledge_base",
        embedding_service: EmbeddingService | None = None,
        chunk_size: int = 500,
        overlap: int = 50,
    ):
        self.embedding_service = embedding_service or EmbeddingService()
        self.chunks: list[dict[str, str]] = []

        documents = load_documents(knowledge_base_dir)

        for document in documents:
            text_chunks = split_into_chunks(
                document["text"],
                chunk_size=chunk_size,
                overlap=overlap,
            )

            for index, chunk in enumerate(text_chunks):
                self.chunks.append(
                    {
                        "text": chunk,
                        "source": document["source"],
                        "chunk_id": str(index),
                    }
                )

        if self.chunks:
            texts = [chunk["text"] for chunk in self.chunks]
            self.embeddings = np.asarray(
                self.embedding_service.embed_texts(texts),
                dtype=np.float32,
            )
        else:
            self.embeddings = np.empty((0, 0), dtype=np.float32)

    def retrieve(self, query: str, top_k: int = 3) -> list[dict]:
        """Return the most relevant chunks for a query."""
        if not isinstance(query, str) or not query.strip():
            raise ValueError("Query must be a non-empty string.")

        if top_k <= 0:
            raise ValueError("top_k must be greater than zero.")

        if not self.chunks:
            return []

        query_embedding = np.asarray(
            self.embedding_service.embed_query(query),
            dtype=np.float32,
        )

        if query_embedding.ndim != 1:
            raise ValueError("Query embedding must be a one-dimensional vector.")

        if query_embedding.shape[0] != self.embeddings.shape[1]:
            raise ValueError("Query and document embedding dimensions do not match.")

        similarities = self.embeddings @ query_embedding
        ranked_indices = np.argsort(similarities)[::-1][:top_k]

        results = []

        for index in ranked_indices:
            chunk = self.chunks[int(index)]
            results.append(
                {
                    "text": chunk["text"],
                    "source": chunk["source"],
                    "chunk_id": chunk["chunk_id"],
                    "similarity": round(float(similarities[index]), 4),
                }
            )

        return results
