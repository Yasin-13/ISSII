import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

# Load datasets
windows_df = pd.read_csv('windows_audit_dataset.csv')
linux_df = pd.read_csv('linux_audit_dataset.csv')
network_df = pd.read_csv('network_audit_dataset.csv')
webserver_df = pd.read_csv('webserver_audit_dataset.csv')

def preprocess(df):
    # Example: Extracting features and labels (this needs to be adjusted based on actual data)
    df['passed'] = df['results'].apply(lambda x: 1 if 'True' in x else 0)
    features = df.drop(columns=['timestamp', 'results'])
    labels = df['passed']
    return features, labels

windows_features, windows_labels = preprocess(windows_df)
linux_features, linux_labels = preprocess(linux_df)
network_features, network_labels = preprocess(network_df)
webserver_features, webserver_labels = preprocess(webserver_df)

# Combine datasets
features = pd.concat([windows_features, linux_features, network_features, webserver_features])
labels = pd.concat([windows_labels, linux_labels, network_labels, webserver_labels])

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.2, random_state=42)

# Train a model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f'Model accuracy: {accuracy:.2f}')

joblib.dump(model, 'audit_predictive_model.pkl')
print('Model saved as audit_predictive_model.pkl')