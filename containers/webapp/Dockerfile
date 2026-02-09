# TechVault Solutions Web Application
# Intentionally vulnerable for purple team testing
FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    iputils-ping \
    net-tools \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./

EXPOSE 8080

ENV FLASK_APP=app.py
ENV FLASK_ENV=production

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
