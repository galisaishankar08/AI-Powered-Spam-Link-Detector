import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import pickle
# Load the dataset
data = pd.read_csv('../out/url_featured_data.csv')

# Split the data into features (X) and the target variable (y)
X = data.drop(['is_vulnerable', 'url'], axis=1).values
Y = data['is_vulnerable']

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(
    X, Y, test_size=0.2, random_state=42)

# Create a Random Forest classifier
rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42)

# Train the classifier on the training data
rf_classifier.fit(X_train, y_train)

# Make predictions on the test data
y_pred = rf_classifier.predict(X_test)

# Evaluate the model
accuracy = accuracy_score(y_test, y_pred)
print(f'Accuracy: {accuracy}')
print(classification_report(y_test, y_pred))

model_filename = '../models/rf_classifier_model.pkl'
with open(model_filename, 'wb') as model_file:
    pickle.dump(rf_classifier, model_file)

# joblib.dump(rf_classifier, model_filename)
print(f"Model saved as {model_filename}")
