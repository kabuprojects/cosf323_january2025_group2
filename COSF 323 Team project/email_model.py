import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

# Step 1: Load the dataset
data = pd.read_csv('emails.csv')  # Ensure this file exists in the same directory
X = data['text']  # Email content
y = data['label']  # Labels (0 for malicious, 1 for genuine)

# Step 2: Preprocess the text data
vectorizer = TfidfVectorizer(stop_words='english', max_features=5000)
X_vectorized = vectorizer.fit_transform(X)

# Step 3: Split the dataset
X_train, X_test, y_train, y_test = train_test_split(X_vectorized, y, test_size=0.2, random_state=42)

# Step 4: Train the model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Step 5: Save the model and vectorizer
joblib.dump(model, 'email_model.pkl')
joblib.dump(vectorizer, 'vectorizer.pkl')
print("Model and vectorizer saved as 'email_model.pkl' and 'vectorizer.pkl'")