"""
ML model check.

Uses the model trained by ml/train_model.py to score how much an
email's wording looks like the phishing emails it learned from.

Why no scikit-learn here? The model is just a list of words with two
numbers each (how rare the word is, and how "phishy" it is). Doing the
math by hand keeps the detector light and dependency-free, which matters
later when it runs on a server or in a browser extension.

Why JSON and not pickle? Loading a pickle file can run code hidden
inside it. A JSON file is only data, so a tampered model can't take over.

LIMITATIONS (be honest about these):
- Trained on mostly 2000s spam vs. internal Enron company email.
- 98.5% accurate on its own test set, but much weaker on modern email.
  In testing it rated a normal "your order has shipped" email 95% phishing
  and a plain CEO gift-card scam only 46%. This is called DATASET SHIFT:
  the training data doesn't look like today's real inbox.
- It only reads words. It knows nothing about links, senders, or headers.
- So for now it is EXPERIMENTAL: its strongest result is "low" (5 points)
  and it can never decide a verdict alone. Retrain on modern data to trust it more.
"""

import json
import math
import re
from functools import lru_cache
from pathlib import Path

from detector.findings import Finding
from detector.language import visible_text

MODEL_PATH = Path(__file__).parent / "model" / "phish_model.json"
MAX_MODEL_SIZE = 5 * 1024 * 1024  # refuse a model file that's suspiciously large

FLAG_AT = 0.90   # model probability needed for a "low" finding (the max it can give)


class ModelError(Exception):
    pass


@lru_cache(maxsize=1)
def load_model(path=MODEL_PATH):
    """Load and check the model once, then reuse it."""
    path = Path(path)
    if not path.is_file():
        raise ModelError(f"Model file not found: {path}. Run ml/train_model.py first.")
    if path.stat().st_size > MAX_MODEL_SIZE:
        raise ModelError("Model file is too large. Refusing to load it.")

    data = json.loads(path.read_text())
    for key in ("version", "token_pattern", "ngram_range", "intercept", "vocab", "stop_words"):
        if key not in data:
            raise ModelError(f"Model file is missing '{key}'.")
    if data["version"] != 1:
        raise ModelError("Unknown model version.")

    return {
        "pattern": re.compile(data["token_pattern"]),
        "ngrams": tuple(data["ngram_range"]),
        "stop": frozenset(data["stop_words"]),
        "max_chars": int(data.get("max_chars", 20_000)),
        "intercept": float(data["intercept"]),
        "vocab": data["vocab"],          # word -> [idf, weight]
    }


def tokens_and_pairs(text, model):
    """Split text into words, then add word pairs. Mirrors scikit-learn exactly."""
    words = [w for w in model["pattern"].findall(text.lower()) if w not in model["stop"]]
    low, high = model["ngrams"]
    terms = list(words) if low == 1 else []
    for n in range(max(low, 2), high + 1):
        terms += [" ".join(words[i:i + n]) for i in range(len(words) - n + 1)]
    return terms


def phishing_probability(text, model=None):
    """
    Returns a number from 0 to 1: how much this text looks like phishing.

    The math (TF-IDF + logistic regression):
    1. Count each known word or pair.
    2. Score = (1 + log(count)) x rarity. Rare, repeated words matter most.
    3. Scale all scores so long and short emails are treated the same.
    4. Add up score x weight for every word, plus a starting value.
    5. Squash the total into 0 to 1 with the sigmoid function.
    """
    model = model or load_model()
    text = text[: model["max_chars"]]

    counts = {}
    for term in tokens_and_pairs(text, model):
        if term in model["vocab"]:
            counts[term] = counts.get(term, 0) + 1

    scores = {t: (1 + math.log(c)) * model["vocab"][t][0] for t, c in counts.items()}
    length = math.sqrt(sum(s * s for s in scores.values())) or 1.0

    total = model["intercept"] + sum(
        (s / length) * model["vocab"][t][1] for t, s in scores.items())
    return 1 / (1 + math.exp(-total))


def analyze_ml(email):
    """Takes a ParsedEmail. Returns a list with one finding about the model's opinion."""
    try:
        model = load_model()
    except (ModelError, ValueError) as err:
        return [Finding("ML model", "info", f"ML check skipped: {err}")]

    text = visible_text(email)
    if len(text.split()) < 5:
        return [Finding("ML model", "info", "ML check skipped: too little text to judge.")]

    prob = phishing_probability(text, model)
    pct = round(prob * 100)

    if prob >= FLAG_AT:
        return [Finding("ML model", "low",
                        f"Experimental model: wording resembles spam/phishing it was trained on "
                        f"({pct}% match). It also flags many normal customer emails, so this "
                        "is a weak clue.")]
    return [Finding("ML model", "info",
                    f"Experimental model: {pct}% phishing match (below the {round(FLAG_AT * 100)}% "
                    "flag line).")]
