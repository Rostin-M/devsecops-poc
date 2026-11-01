# Dockerfile con malas prácticas a propósito (Trivy las reporta como misconfiguraciones)
FROM python:3.9

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app.py .

# Corre como root y sin HEALTHCHECK
EXPOSE 8080
CMD ["python", "app.py"]
