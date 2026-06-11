# Gunakan base image Python versi slim agar ukuran image ringan
FROM python:3.11-slim

# Set working directory di dalam container
WORKDIR /app

# Mengatur environment variables untuk optimasi Python di dalam Docker
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:create_app()"]