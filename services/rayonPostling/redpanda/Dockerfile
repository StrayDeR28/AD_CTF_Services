FROM docker.redpanda.com/redpandadata/redpanda:latest

WORKDIR /var/lib/redpanda

# Создаём директорию для данных и задаём права
RUN mkdir -p /var/lib/redpanda/data && chown redpanda:redpanda /var/lib/redpanda/data

# Открываем порт Kafka API
EXPOSE 9092

# Используем entrypoint.sh как в официальном образе
ENTRYPOINT ["/entrypoint.sh", "redpanda", "start", "--node-id", "0", "--check=false"]
