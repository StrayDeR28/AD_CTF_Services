FROM ubuntu:22.04

RUN apt-get update --fix-missing -o Acquire::http::Timeout=10 \
    && apt-get install -y --no-install-recommends \
    libsodium23 \
    librdkafka1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY mail_panda .
RUN chmod +x mail_panda

EXPOSE 31337
CMD ["./mail_panda"]