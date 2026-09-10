# KronoDroid Experiments

This directory contains clean experiment notebooks aligned with the paper's current positioning: models are evaluation probes for temporal behavioral drift, not the main novelty.

- `kronodroid_tabular_models.ipynb`: trains Logistic Regression, Random Forest, Extra Trees, XGBoost when available, and MLP on KronoDroid tabular behavioral profiles, then exports every trained pipeline for temporal inference.
- `kronodroid_sequence_models.ipynb`: trains BiLSTM and Transformer models on KronoDroid event-sequence traces.
- `androzoo_tabular_model_inference.ipynb`: applies all exported KronoDroid tabular models to the balanced AndroZoo temporal hold-out without retraining.

Both notebooks use only KronoDroid train/validation splits. Vocabulary, preprocessing, scaling, and model selection are fit only on the training split. Results are written under `results/`.
