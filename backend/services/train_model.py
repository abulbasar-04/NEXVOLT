
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

from services.feature_extraction import extract_url_features


# ==========================================
# 1. LOAD DATASET
# ==========================================

print("Loading dataset...")

df = pd.read_csv(
    "PhiUSIIL_Phishing_URL_Dataset.csv"
)

print("Dataset loaded:", len(df), "URLs")


# ==========================================
# 2. EXTRACT URL FEATURES
# ==========================================

print("\nExtracting URL features...")

features_list = []

for url in df["URL"]:

    features = extract_url_features(url)

    features_list.append(features)

X = pd.DataFrame(features_list)

y = df["label"]


print("Features extracted:", X.shape)


# ==========================================
# 3. SPLIT DATASET
# ==========================================

print("\nSplitting dataset...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("Training samples:", len(X_train))
print("Testing samples:", len(X_test))


# ==========================================
# 4. TRAIN RANDOM FOREST
# ==========================================

print("\nTraining Random Forest model...")

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(X_train, y_train)

print("Training completed!")


# ==========================================
# 5. MODEL EVALUATION
# ==========================================

print("\nEvaluating model...")

predictions = model.predict(X_test)

accuracy = accuracy_score(
    y_test,
    predictions
)

print("\nAccuracy:", round(accuracy * 100, 2), "%")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions,
        target_names=["Phishing", "Legitimate"]
    )
)

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, predictions))


# ==========================================
# 6. SAVE MODEL
# ==========================================

print("\nSaving model...")

joblib.dump(
    model,
    "services/phishing_model.pkl"
)

print("\nModel saved successfully!")
print("File: services/phishing_model.pkl")
