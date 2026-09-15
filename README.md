# 🛡️ Network Intrusion Detection System (NIDS)

A machine learning-based system that classifies network traffic as **Normal** or **Attack**, built on the NSL-KDD dataset. Includes a full training pipeline and an interactive Streamlit demo app.

## Overview

Traditional intrusion detection systems rely on fixed rules and known attack signatures, making them ineffective against novel threats. This project explores a machine learning approach — training classifiers to recognize patterns in network traffic that indicate malicious activity, rather than relying on predefined rules.

## Dataset

- **NSL-KDD** — an improved version of the classic KDD Cup 99 dataset, widely used in NIDS research
- 125,973 training samples, 22,544 test samples, 41 features per connection
- 23 attack types (e.g., neptune, smurf, satan) consolidated into a binary label: `normal` vs `attack`

## Approach

1. **Preprocessing** — encoded categorical features (`protocol_type`, `service`, `flag`), created binary labels
2. **Model training** — compared Decision Tree, Random Forest, Logistic Regression, and XGBoost
3. **Evaluation** — accuracy, precision, recall, F1-score, and confusion matrix, with particular focus on **attack recall** (missing a real attack is more costly than a false alarm)
4. **Validation** — 5-fold cross-validation to confirm results are consistent, not a lucky split
5. **Deployment** — best model (XGBoost) wrapped in an interactive Streamlit app

## Results

| Model | Accuracy | Attack Recall |
|---|---|---|
| Decision Tree | 78.96% | 65.3% |
| Random Forest | 77.27% | 62.2% |
| Logistic Regression | 75.39% | 61.8% |
| XGBoost | 80.48% | 67.9% |

**Note:** the results above use NSL-KDD's official train/test split, which deliberately includes attack patterns not seen during training — simulating detection of unknown, real-world attacks. Under a random stratified split (train and test drawn from the same pool), the same models reach **~99.6% cross-validated accuracy**. Both numbers are reported here intentionally: the lower one reflects realistic generalization to unseen threats, while the higher one reflects standard evaluation practice. The gap itself is a meaningful finding about the limits of ML-based intrusion detection.

## Tech Stack

- **Language:** Python
- **ML/Data:** scikit-learn, XGBoost, pandas, NumPy
- **Visualization:** Matplotlib, Seaborn
- **Prototype:** Streamlit
- **Environment:** VS Code, Jupyter

## Project Structure
nids/
├── data/
│ ├── KDDTrain+.txt
│ ├── KDDTest+.txt
│ ├── eda.ipynb # data exploration, preprocessing, model training
│ ├── app.py # Streamlit demo app
│ ├── nids_model.pkl # saved trained model
│ └── model_columns.pkl # saved feature columns
└── README.md

## Running the Demo

```bash
pip install -r requirements.txt
streamlit run data/app.py
```

## Future Work

- Hyperparameter tuning via RandomizedSearchCV
- Multi-class classification (DoS, Probe, R2L, U2R attack categories)
- Testing on additional datasets (e.g., CICIDS2017, UNSW-NB15)
- Handling class imbalance with SMOTE

## References

- Tavallaee, M., Bagheri, E., Lu, W., & Ghorbani, A. (2009). *A Detailed Analysis of the KDD CUP 99 Data Set.*
- NSL-KDD Dataset — Canadian Institute for Cybersecurity, University of New Brunswick
- [scikit-learn documentation](https://scikit-learn.org)
- [Streamlit documentation](https://docs.streamlit.io)
