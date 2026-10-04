import os
import joblib
import numpy as np

from sklearn.ensemble import RandomForestClassifier


MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(
    MODEL_DIR,
    "url_phishing_model.joblib"
)


FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "path_length",
    "subdomain_count",
    "has_https",
    "has_ip_address",
    "has_at_symbol",
    "has_dash_in_domain",
    "has_suspicious_keyword",
    "has_punycode",
    "has_port",
    "certificate_valid",
    "certificate_expired",
    "hostname_match",
    "certificate_days_remaining",
    "redirect_count",
    "dns_available"
]


def create_training_data():
    """
    Creates a small synthetic training dataset
    for the prototype.

    This is NOT a production phishing dataset.
    Replace it later with a real labeled dataset.
    """

    rng = np.random.default_rng(42)

    samples = []
    labels = []

    for _ in range(2000):

        url_length = rng.integers(20, 250)
        domain_length = rng.integers(5, 80)
        path_length = rng.integers(0, 180)
        subdomain_count = rng.integers(0, 6)

        has_https = rng.integers(0, 2)
        has_ip_address = rng.integers(0, 2)
        has_at_symbol = rng.integers(0, 2)
        has_dash_in_domain = rng.integers(0, 2)
        has_suspicious_keyword = rng.integers(0, 2)
        has_punycode = rng.integers(0, 2)
        has_port = rng.integers(0, 2)

        certificate_valid = rng.integers(0, 2)
        certificate_expired = rng.integers(0, 2)
        hostname_match = rng.integers(0, 2)

        certificate_days_remaining = rng.integers(
            -100,
            500
        )

        redirect_count = rng.integers(0, 6)
        dns_available = rng.integers(0, 2)

        risk_score = 0

        if url_length > 100:
            risk_score += 1

        if domain_length > 40:
            risk_score += 1

        if path_length > 80:
            risk_score += 1

        if subdomain_count >= 3:
            risk_score += 1

        if not has_https:
            risk_score += 2

        if has_ip_address:
            risk_score += 3

        if has_at_symbol:
            risk_score += 3

        if has_dash_in_domain:
            risk_score += 1

        if has_suspicious_keyword:
            risk_score += 2

        if has_punycode:
            risk_score += 3

        if has_port:
            risk_score += 1

        if not certificate_valid:
            risk_score += 2

        if certificate_expired:
            risk_score += 3

        if not hostname_match:
            risk_score += 3

        if certificate_days_remaining < 0:
            risk_score += 2

        if redirect_count >= 3:
            risk_score += 2

        if not dns_available:
            risk_score += 2

        # Add a little noise so the model
        # does not simply memorize one rule.
        risk_score += rng.integers(-1, 2)

        label = 1 if risk_score >= 7 else 0

        samples.append([
            url_length,
            domain_length,
            path_length,
            subdomain_count,
            has_https,
            has_ip_address,
            has_at_symbol,
            has_dash_in_domain,
            has_suspicious_keyword,
            has_punycode,
            has_port,
            certificate_valid,
            certificate_expired,
            hostname_match,
            certificate_days_remaining,
            redirect_count,
            dns_available
        ])

        labels.append(label)

    return np.array(samples), np.array(labels)


def train_model():
    """
    Train and save the Random Forest model.
    """

    X, y = create_training_data()

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        random_state=42,
        class_weight="balanced"
    )

    model.fit(X, y)

    joblib.dump(
        {
            "model": model,
            "features": FEATURE_NAMES
        },
        MODEL_PATH
    )

    print(
        "URL phishing AI model trained successfully."
    )

    print(
        f"Saved to: {MODEL_PATH}"
    )


def load_model():

    if not os.path.exists(MODEL_PATH):
        train_model()

    package = joblib.load(MODEL_PATH)

    return (
        package["model"],
        package["features"]
    )


def predict_url(features):

    model, feature_names = load_model()

    values = [
        features.get(name, 0)
        for name in feature_names
    ]

    X = np.array(
        [values],
        dtype=float
    )

    probability = model.predict_proba(X)[0][1]

    prediction = int(
        model.predict(X)[0]
    )

    return {
        "prediction": prediction,
        "phishing_probability": round(
            float(probability) * 100,
            2
        )
    }


if __name__ == "__main__":
    train_model()