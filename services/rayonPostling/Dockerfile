FROM python:3.11-slim

WORKDIR /app

# Установка системных зависимостей
RUN apt-get update
RUN apt-get install -y \
    gcc \
    libffi-dev \
    libssl-dev \
    libjpeg-dev \
    zlib1g-dev \
    build-essential \
    libfreetype6-dev \
    libpng-dev \
    fonts-dejavu-core
RUN rm -rf /var/lib/apt/lists/*

# Установка зависимостей Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем проект
COPY . .

# Создание необходимых директорий
RUN mkdir -p static/postcards static/temp

# Установка переменных окружения для подключения к Redis
ENV REDIS_HOST=redis
ENV REDIS_PORT=6379

EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
