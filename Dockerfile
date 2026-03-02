FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for tkinter (headless/VNC use)
RUN apt-get update && apt-get install -y \
    python3-tk \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV DISPLAY=:0

ENTRYPOINT ["python", "app.py"]
