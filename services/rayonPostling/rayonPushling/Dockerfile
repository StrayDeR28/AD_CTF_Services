FROM ubuntu:22.04

# Установка базовых зависимостей
RUN apt-get update --fix-missing -o Acquire::http::Timeout=10 \
    && apt-get install -y --no-install-recommends \
    ca-certificates \
    libsodium-dev \
    librdkafka-dev \
    libcjson-dev \
    g++ \
    cmake \
    git \
    build-essential \
    pkg-config \
    libssl-dev \
    libabsl-dev \
    libc-ares-dev \  # <-- Вот правильное имя
    && rm -rf /var/lib/apt/lists/*
    
# Установка gRPC
RUN apt-get install -y libgrpc-dev libgrpc++-dev protobuf-compiler-grpc

WORKDIR /app
COPY mail_panda.c .
COPY mail_panda.proto .

# Компиляция с подробным выводом ошибок
RUN protoc --cpp_out=. mail_panda.proto \
    && protoc --grpc_out=. --plugin=protoc-gen-grpc=/usr/bin/grpc_cpp_plugin mail_panda.proto \
    && g++ -o mail_panda mail_panda.c mail_panda.pb.cc mail_panda.grpc.pb.cc \
       -L/usr/local/lib \
       -lgrpc++ -lgrpc -lgpr -lprotobuf -labsl_synchronization -labsl_base -labsl_raw_logging_internal \
       -labsl_time -labsl_stacktrace -labsl_symbolize -labsl_strings -labsl_status \
       -lsodium -lrdkafka -lcjson -pthread -lz -lcares -lssl -lcrypto \
       -Wall -Werror -Wl,--verbose

RUN chmod +x mail_panda
EXPOSE 50051
CMD ["./mail_panda"]
