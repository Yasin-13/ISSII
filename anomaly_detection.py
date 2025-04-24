import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

network_data = pd.read_csv('network_audit_dataset.csv')

features = network_data.drop(columns=['timestamp', 'event'])
scaler = StandardScaler()
scaled_features = scaler.fit_transform(features)

model = IsolationForest(contamination=0.01, random_state=42)
model.fit(scaled_features)

joblib.dump(model, 'network_anomaly_detection_model.pkl')
print('Anomaly detection model saved as network_anomaly_detection_model.pkl')

# Function to predict anomalies in new data
def predict_anomalies(new_data):
    scaled_data = scaler.transform(new_data)
    predictions = model.predict(scaled_data)
    anomalies = new_data[predictions == -1]
    return anomalies

# Example usage
new_data = pd.read_csv('new_network_data.csv')
anomalies = predict_anomalies(new_data)
print('Detected anomalies:')
print(anomalies)