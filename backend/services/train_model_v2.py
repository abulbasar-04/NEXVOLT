import pandas as pd
import joblib

from pathlib import Path
from urllib.parse import urlparse

from sklearn.model_selection import GroupShuffleSplit
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    balanced_accuracy_score,
)

from services.feature_extraction import extract_url_features


BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR.parent / "PhiUSIIL_Phishing_URL_Dataset.csv"
MODEL_PATH = BASE_DIR / "phishing_model_v2_candidate.pkl"


def get_domain(url):
    host = (urlparse(str(url)).hostname or "").lower()
    return host.removeprefix("www.")


print("\n===== NEXVOLT ML TRAINING V2 =====")

# 1. Load dataset
df = pd.read_csv(DATASET_PATH)
df = df.dropna(subset=["URL", "label"]).copy()

df["label"] = df["label"].astype(int)
df["domain_group"] = df["URL"].apply(get_domain)

print("Dataset rows:", len(df))
print("Labels:", df["label"].value_counts().to_dict())
print("Unique domains:", df["domain_group"].nunique())

# 2. Extract features
print("\nExtracting features...")
X = pd.DataFrame(
    [extract_url_features(url) for url in df["URL"]]
)

y = df["label"]
groups = df["domain_group"]

# 3. Group-aware split
splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42,
)

train_idx, test_idx = next(
    splitter.split(X, y, groups=groups)
)

X_train = X.iloc[train_idx]
X_test = X.iloc[test_idx]

y_train = y.iloc[train_idx]
y_test = y.iloc[test_idx]

train_domains = set(groups.iloc[train_idx])
test_domains = set(groups.iloc[test_idx])

overlap = train_domains.intersection(test_domains)

print("\nTrain rows:", len(train_idx))
print("Test rows:", len(test_idx))
print("Train domains:", len(train_domains))
print("Test domains:", len(test_domains))
print("Domain overlap:", len(overlap))

assert len(overlap) == 0, "Domain leakage detected!"

# 4. Train model
print("\nTraining Random Forest...")

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced",
    min_samples_leaf=2,
)

model.fit(X_train, y_train)

# 5. Evaluate
predictions = model.predict(X_test)

print("\n===== EVALUATION =====")
print("Accuracy:", round(accuracy_score(y_test, predictions), 4))
print(
    "Balanced Accuracy:",
    round(balanced_accuracy_score(y_test, predictions), 4),
)

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["Phishing", "Legitimate"],
        zero_division=0,
    )
)

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, predictions, labels=[0, 1]))

# 6. Save candidate only
joblib.dump(model, MODEL_PATH)

print("\nCandidate model saved:")
print(MODEL_PATH)
print("\nExisting production model remains unchanged.")
