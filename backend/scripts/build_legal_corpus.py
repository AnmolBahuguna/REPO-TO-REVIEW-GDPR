from __future__ import annotations

import csv
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT.parent
SOURCES = [
    ("UK GDPR", PROJECT / "data.csv"),
    ("Data Protection Act 2018", PROJECT / "data-_1_.csv"),
    ("Data (Use and Access) Act 2025", PROJECT / "data-_2_.csv"),
]
OUTPUT = ROOT / "data" / "legal_law_corpus.csv"


def rows_from_source(document: str, path: Path, document_number: int):
    if not path.is_file():
        raise FileNotFoundError(f"Required law CSV is missing: {path}")
    page_lines: list[str] = []
    page_number = 1
    with path.open("r", encoding="utf-8-sig", newline="") as source_file:
        for row in csv.reader(source_file):
            line = row[0] if row else ""
            pieces = line.split("\f")
            for index, piece in enumerate(pieces):
                if piece.strip():
                    page_lines.append(piece.strip())
                if index < len(pieces) - 1:
                    text = re.sub(r"\s+", " ", " ".join(page_lines)).strip()
                    if text:
                        yield {
                            "record_id": f"UKLAW-{document_number}-{page_number:04d}",
                            "source_document": document,
                            "source_file": path.name,
                            "jurisdiction": "UK",
                            "page": page_number,
                            "provision_reference": "",
                            "text": text,
                        }
                    page_number += 1
                    page_lines = []
    text = re.sub(r"\s+", " ", " ".join(page_lines)).strip()
    if text:
        yield {
            "record_id": f"UKLAW-{document_number}-{page_number:04d}",
            "source_document": document,
            "source_file": path.name,
            "jurisdiction": "UK",
            "page": page_number,
            "provision_reference": "",
            "text": text,
        }


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with OUTPUT.open("w", encoding="utf-8-sig", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=[
            "record_id", "source_document", "source_file", "jurisdiction", "page", "provision_reference", "text",
        ])
        writer.writeheader()
        for document_number, (document, path) in enumerate(SOURCES, start=1):
            document_count = 0
            for record in rows_from_source(document, path, document_number):
                writer.writerow(record)
                count += 1
                document_count += 1
            print(f"{document}: {document_count} pages from {path.name}")
    print(f"Wrote {count} page records to {OUTPUT}")


if __name__ == "__main__":
    main()
