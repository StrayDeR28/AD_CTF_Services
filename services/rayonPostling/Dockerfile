FROM python:3.11-slim

WORKDIR /app

# Установка системных зависимостей
RUN apt-get update \
    && apt-get install -y \
       gcc \
       libffi-dev \
       libssl-dev \
       libjpeg-dev \
       zlib1g-dev \
       build-essential \
       libfreetype6-dev \
       libpng-dev \
       fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# Установка зависимостей Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем проект
COPY . .

# Создание необходимых директорий
RUN mkdir -p static/postcards static/temp

EXPOSE 5000
CMD ["python", "app.py"]
