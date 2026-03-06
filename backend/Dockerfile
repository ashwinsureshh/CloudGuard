FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Create model directory so the volume mount has a target
RUN mkdir -p /app/model

EXPOSE 5001

CMD ["python", "app.py"]
