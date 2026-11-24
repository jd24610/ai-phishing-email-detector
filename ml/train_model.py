"""
Train the phishing text classifier.

This is a DEVELOPER script. You run it once to build the model.
The detector itself doesn't need pandas or scikit-learn: it loads
the finished model from a plain JSON file (see detector/ml.py).

Usage (from the project folder):
    pip install -r requirements-dev.txt
    python3 ml/train_model.py

Dataset: "Phishing_Email.csv" (public, also on Kaggle and Hugging Face).
Put it at data/Phishing_Email.csv. It is NOT committed to GitHub.

Steps:
1. Load and clean the data
2. Split into training and test sets BEFORE training (the test set stays unseen)
3. Turn text into numbers (TF-IDF)
4. Train two models and compare them
5. Measure precision, recall, and errors on the unseen test set
6. Show which words the model leans on (to catch shortcuts)
7. Export the model to JSON
"""

import json
import sys
from pathlib import Path

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "Phishing_Email.csv"
OUT = ROOT / "detector" / "model" / "phish_model.json"

# Same settings MUST be used in detector/ml.py when predicting.
# Letters only, no numbers. The first version learned that "2004" and "2005"
# meant phishing and "2001" meant safe, just because of when the emails were
# collected. Years and phone codes tell us nothing about a 2026 email.
TOKEN_PATTERN = r"(?u)\b[^\W\d_]{2,}\b"
NGRAMS = (1, 2)                     # single words and word pairs

# Words that only identify WHERE the dataset came from, not whether an email
# is phishing. Most safe emails are from Enron (Houston, 2001) and a
# linguistics mailing list. Most phishing came via SpamAssassin archives.
# Left in, the model learns "mentions Enron = safe", which is useless.
DATASET_SHORTCUTS = [
    "enron", "ect", "hou", "houston", "vince", "kaminski", "louise", "kitchen",
    "shirley", "crenshaw", "vkaminski", "aol", "cc", "subject", "re", "fw",
    "linguistics", "linguist", "language", "languages", "university", "edu",
    "spamassassin", "sightings", "url", "wrote", "date", "list", "mailing",
    "sourceforge", "lists", "listinfo", "razor", "exmh", "users", "ilug",
]
MAX_FEATURES = 20_000               # keep the 20k most useful words/pairs
MAX_CHARS = 20_000                  # only look at the first 20k characters of each email


def load_data():
    if not DATA.is_file():
        sys.exit(f"Dataset not found at {DATA}. See the instructions at the top of this file.")

    df = pd.read_csv(DATA)
    df = df.rename(columns={"Email Text": "text", "Email Type": "label"})[["text", "label"]]

    before = len(df)
    df = df.dropna(subset=["text"])
    df["text"] = df["text"].astype(str).str.slice(0, MAX_CHARS)
    df = df[df["text"].str.strip().str.len() >= 20]       # drop empty or near-empty rows
    df = df.drop_duplicates(subset=["text"])               # duplicates would leak into the test set
    df["y"] = (df["label"] == "Phishing Email").astype(int)

    print(f"Rows: {before} loaded, {len(df)} after cleaning "
          f"({before - len(df)} removed: empty, too short, or duplicate)")
    print(f"Phishing: {df.y.sum()}   Safe: {(df.y == 0).sum()}\n")
    return df


def main():
    df = load_data()

    # 2. Split FIRST. 80% to learn from, 20% locked away for the final exam.
    # stratify keeps the same phishing/safe ratio in both halves.
    train, test = train_test_split(df, test_size=0.2, random_state=42, stratify=df.y)

    # 3. TF-IDF: each email becomes a list of word scores.
    # Common words everywhere ("the") score low. Words that are frequent in
    # this email but rare overall score high.
    vec = TfidfVectorizer(lowercase=True, token_pattern=TOKEN_PATTERN, ngram_range=NGRAMS,
                          max_features=MAX_FEATURES, min_df=3, sublinear_tf=True,
                          stop_words=DATASET_SHORTCUTS)
    X_train = vec.fit_transform(train.text)   # learn the vocabulary from TRAINING data only
    X_test = vec.transform(test.text)

    # 4. Two simple, explainable models.
    models = {
        "Naive Bayes": MultinomialNB(),
        "Logistic Regression": LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced"),
    }
    for name, model in models.items():
        model.fit(X_train, train.y)
        pred = model.predict(X_test)
        print("=" * 60)
        print(name)
        print("=" * 60)
        print(classification_report(test.y, pred, target_names=["Safe", "Phishing"], digits=3))
        tn, fp, fn, tp = confusion_matrix(test.y, pred).ravel()
        print(f"Safe emails wrongly flagged (false positives): {fp}")
        print(f"Phishing emails missed (false negatives):      {fn}\n")

    # We keep Logistic Regression: its weights are easy to read and export.
    model = models["Logistic Regression"]

    # 6. What did it learn? Look for shortcuts.
    vocab = vec.get_feature_names_out()
    weights = model.coef_[0]
    order = weights.argsort()
    print("Words pushing toward PHISHING:", ", ".join(vocab[i] for i in order[-25:][::-1]))
    print("\nWords pushing toward SAFE:    ", ", ".join(vocab[i] for i in order[:25]))

    # 7. Export to JSON. We avoid pickle/joblib on purpose: loading a pickle
    # file can run code, so a tampered model file could take over the program.
    # JSON is just data.
    keep = range(len(vocab))  # keep every feature, they all count toward the length normalizing
    export = {
        "version": 1,
        "dataset": "Phishing_Email.csv (18,650 emails; mostly 2000s spam vs. Enron/SpamAssassin ham)",
        "token_pattern": TOKEN_PATTERN,
        "stop_words": sorted(DATASET_SHORTCUTS),
        "ngram_range": list(NGRAMS),
        "max_chars": MAX_CHARS,
        "intercept": float(model.intercept_[0]),
        "vocab": {vocab[i]: [round(float(vec.idf_[i]), 6), round(float(weights[i]), 6)]
                  for i in keep},
    }
    OUT.write_text(json.dumps(export, separators=(",", ":")))
    print(f"\nSaved {len(keep)} features to {OUT.relative_to(ROOT)} "
          f"({OUT.stat().st_size // 1024} KB)")

    # Save a small test file so detector/ml.py can prove it gives the same answers.
    check = test.sample(200, random_state=0)
    probs = model.predict_proba(vec.transform(check.text))[:, 1]
    (ROOT / "ml" / "parity_check.json").write_text(json.dumps(
        [{"text": t, "prob": round(float(p), 6)} for t, p in zip(check.text, probs)]))


if __name__ == "__main__":
    main()
