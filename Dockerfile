# Минимальный образ для выполнения
FROM ubuntu:22.04

# Устанавливаем runtime-зависимости
RUN apt-get update && apt-get install -y \
    libsodium23 \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Создаём рабочую директорию
WORKDIR /app

# Копируем готовый бинарник
COPY mail_inet .

# Даём права на выполнение
RUN chmod +x mail_inet

# Указываем команду для запуска
CMD ["./mail_inet"]
