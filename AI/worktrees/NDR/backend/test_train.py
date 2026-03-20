from utils import parse_logs
from ml_model import train_anomaly_model

with open("sample_logs.txt", "r") as f:
    raw_logs = f.read()

parsed_logs = parse_logs(raw_logs)
model_path = train_anomaly_model(parsed_logs)

print("Model saved at:", model_path)