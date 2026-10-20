# Optional labeled seed dataset

`legal_law_corpus.csv` is built from the root CSVs `data.csv`, `data-_1_.csv`, and `data-_2_.csv`. It contains page text and citation metadata for the supplied UK GDPR, Data Protection Act 2018, and Data (Use and Access) Act 2025. The RAG pipeline chunks these pages and indexes them for legal passage retrieval in chatbot answers and scan reports. This is an unlabelled legal corpus, not a supervised training dataset for `train_model.py`.

Place user-provided seed files in this directory:

- `code_to_gdpr_seed_dataset.jsonl`
- `code_to_gdpr_seed_dataset.csv`

The scanner release did not include either file. Each JSONL object or CSV row must have `code` (or `code_snippet`, `snippet`, `source`, `text`) and `label` (or `expected_label`, `classification`). Labels: `positive` (reviewed privacy signal), `negative` (reviewed safe example), `requires_context` (insufficient evidence); `uncertain` is accepted as an alias for `requires_context`.

Recommended metadata: `sample_id`, `language`, `framework`, `data_category`, `pattern_type`, `category`, `evidence_lines`, `rule_id`, `jurisdiction`, `severity`, `review_notes`, and `group_id`. Use the same `group_id` for semantically related variants, even if their code differs, so related examples cannot leak across train, validation, and test splits. Include safe and risky versions of similar code patterns. Sanitize secrets and personal data, check source licenses, and have labels reviewed by people familiar with the code and privacy context. For stronger estimates of real-repository performance, also reserve complete repositories as a separate evaluation set; snippet-level group splits alone do not establish generalization to unseen repositories.

The loader and pipeline do not create, augment, or infer dataset labels. A dataset is not considered real-world ground truth or legal validation. Current training requires all three labels, at least 3 distinct groups per label, and 15 groups overall. Train only after collecting enough distinct reviewed groups; keep an independent repository-level evaluation set for later release checks.
