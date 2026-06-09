# syntax=docker/dockerfile:1
FROM python:3.12-slim

# Honeypot HTTP — émulation WordPress (Epic 2). Conteneur durci, lab uniquement.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /srv

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Exécution en utilisateur non-root.
RUN useradd --create-home --uid 1000 honeypot
USER honeypot

EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
