# TechVault Solutions Web Application
# Intentionally vulnerable for purple team testing
FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    iputils-ping \
    net-tools \
    curl \
    rsyslog \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN mkdir -p /var/log/gunicorn

EXPOSE 8080

ENV FLASK_APP=app.py
ENV FLASK_ENV=production

ENTRYPOINT ["/entrypoint.sh"]
