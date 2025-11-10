import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_CSV = os.path.join(BASE_DIR, "data", "dataset.csv")
ARTIFACTS_DIR = os.path.join(BASE_DIR, "artifacts")
os.makedirs(ARTIFACTS_DIR, exist_ok=True)

df = pd.read_csv(DATA_CSV)
X = df['query']
y = df['label']

vectorizer = CountVectorizer()
X_vect = vectorizer.fit_transform(X)

model = RandomForestClassifier(n_estimators=100)
model.fit(X_vect, y)

joblib.dump(model, os.path.join(ARTIFACTS_DIR, "model.pkl"))
joblib.dump(vectorizer, os.path.join(ARTIFACTS_DIR, "vectorizer.pkl"))

print("Training complete. Artifacts saved.")
