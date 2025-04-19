# Используем Ubuntu 22.04 как базовый образ
FROM ubuntu:22.04

# Устанавливаем runtime-зависимости
RUN apt-get update --fix-missing -o Acquire::http::Timeout=10 \
    && apt-get install -y --no-install-recommends \
    libsodium23 \
    librdkafka1 \
    && rm -rf /var/lib/apt/lists/*
# Создаём рабочую директорию
WORKDIR /app

# Копируем готовый бинарный файл
COPY mail_panda .

# Делаем бинарник исполняемым
RUN chmod +x mail_panda

# Открываем порт 31337
EXPOSE 31337

# Запускаем бинарник
CMD ["./mail_panda"]
