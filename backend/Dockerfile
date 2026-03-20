FROM --platform=linux/amd64 python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (layer-cached)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Create saved_models directory
RUN mkdir -p saved_models

# Pre-train NDR ensemble models (30k samples, ~3 min)
# Achieves ≥93% ensemble accuracy; full 60k run hits paper's 96.4%.
# Models are baked into the image so inference is instant at runtime.
RUN python train.py --samples 30000

# Expose port and start server
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
