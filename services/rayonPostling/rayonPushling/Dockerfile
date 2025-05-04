FROM ubuntu:22.04

# Установка xinetd и необходимых библиотек
RUN apt-get update --fix-missing -o Acquire::http::Timeout=10 \
    && apt-get install -y --no-install-recommends \
    xinetd \
    libsodium23 \
    libhiredis-dev \
    && rm -rf /var/lib/apt/lists/*

RUN touch /var/log/xinetd.log && chmod 666 /var/log/xinetd.log

# Установка рабочей директории
WORKDIR /app

# Копирование бинарного файла и конфигурации xinetd
COPY mail_panda .
COPY xinetd.conf /etc/xinetd.d/mail_panda

# Даем права на выполнение
RUN chmod +x mail_panda

# Экспонируем порт
EXPOSE 31337

# Запуск xinetd
CMD ["xinetd", "-dontfork"]
