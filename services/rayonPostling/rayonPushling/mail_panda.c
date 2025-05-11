#include <grpc/grpc.h>
#include <grpcpp/server_builder.h>
#include <sodium.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <librdkafka/rdkafka.h>
#include <time.h>
#include <cjson/cJSON.h>
#include "mail_panda.grpc.pb.h"

#define MAX_LEN 64
#define KEY_SIZE crypto_stream_chacha20_KEYBYTES
#define NONCE_SIZE crypto_stream_chacha20_NONCEBYTES
#define POLL_TIMEOUT_MS 1000
#define TOPIC "user-messages"
#define BROKER "redpanda:9092"

static const uint8_t nonce[NONCE_SIZE] = {0};
static const uint8_t key[KEY_SIZE] = {
    0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63,
    0x6B, 0x20, 0x62, 0x72, 0x6F, 0x77, 0x6E, 0x20,
    0x66, 0x6F, 0x78, 0x20, 0x6A, 0x75, 0x6D, 0x70,
    0x73, 0x20, 0x6F, 0x76, 0x65, 0x72, 0x20, 0x6C
};

int hex_to_bin(const char *hex, uint8_t *bin, size_t bin_size) {
    size_t hex_len = strlen(hex);
    if (hex_len > 0 && hex[hex_len - 1] == '\n') hex_len--;
    if (hex_len > 0 && hex[hex_len - 1] == '\r') hex_len--;
    if (hex_len % 2 != 0 || hex_len / 2 > bin_size) return -1;
    for (size_t i = 0; i < hex_len / 2; i++) {
        sscanf(hex + (i * 2), "%2hhx", &bin[i]);
    }
    return hex_len / 2;
}

int decrypt_token(const char *token_hex, char *login) {
    uint8_t encrypted[MAX_LEN] = {0};
    int encrypted_len = hex_to_bin(token_hex, encrypted, MAX_LEN);
    if (encrypted_len < 0) {
        return -1;
    }
    crypto_stream_chacha20_xor((uint8_t*)login, encrypted, encrypted_len, nonce, key);
    login[encrypted_len] = '\0';
    return 0;
}

void cleanup(rd_kafka_t *rk) {
    if (rk) {
        rd_kafka_consumer_close(rk);
        rd_kafka_destroy(rk);
    }
}

rd_kafka_t *create_consumer(const char *group_id, const char *offset_reset) {
    rd_kafka_conf_t *conf = rd_kafka_conf_new();
    char errstr[512];

    rd_kafka_conf_set(conf, "bootstrap.servers", BROKER, errstr, sizeof(errstr));
    rd_kafka_conf_set(conf, "log_level", "3", errstr, sizeof(errstr));
    rd_kafka_conf_set(conf, "group.id", group_id, errstr, sizeof(errstr));
    rd_kafka_conf_set(conf, "auto.offset.reset", offset_reset, errstr, sizeof(errstr));

    rd_kafka_t *rk = rd_kafka_new(RD_KAFKA_CONSUMER, conf, errstr, sizeof(errstr));
    if (!rk) {
        fprintf(stderr, "Ошибка создания Kafka-потребителя: %s\n", errstr);
        cleanup(NULL);
    }
    return rk;
}

void subscribe_to_topic(rd_kafka_t *rk, const char *topic) {
    rd_kafka_topic_partition_list_t *topics = rd_kafka_topic_partition_list_new(1);
    rd_kafka_topic_partition_list_add(topics, (char *)topic, RD_KAFKA_PARTITION_UA);
    if (rd_kafka_subscribe(rk, topics) != RD_KAFKA_RESP_ERR_NO_ERROR) {
        fprintf(stderr, "Ошибка подписки на топик %s\n", topic);
        rd_kafka_topic_partition_list_destroy(topics);
        cleanup(rk);
        return;
    }
    rd_kafka_topic_partition_list_destroy(topics);
}

void get_messages(const char *login, grpc::ServerWriter<mail_panda::Message>* writer) {
    rd_kafka_t *rk = create_consumer(login, "earliest");
    subscribe_to_topic(rk, TOPIC);

    int64_t current_time_ms = (int64_t)time(NULL) * 1000;

    while (1) {
        rd_kafka_message_t *msg = rd_kafka_consumer_poll(rk, POLL_TIMEOUT_MS);
        if (!msg) break;
        if (msg->err == RD_KAFKA_RESP_ERR__PARTITION_EOF) {
            rd_kafka_message_destroy(msg);
            break;
        }
        if (msg->err == RD_KAFKA_RESP_ERR_NO_ERROR) {
            cJSON *json = cJSON_Parse((char*)msg->payload);
            if (!json) {
                fprintf(stderr, "Ошибка парсинга JSON: %s\n", cJSON_GetErrorPtr());
                rd_kafka_message_destroy(msg);
                continue;
            }

            cJSON *receiver_login = cJSON_GetObjectItem(json, "receiver_login");
            cJSON *message = cJSON_GetObjectItem(json, "message");
            cJSON *created_at = cJSON_GetObjectItem(json, "created_at");

            if (receiver_login && message && created_at && cJSON_IsString(receiver_login) &&
                cJSON_IsString(message) && cJSON_IsNumber(created_at)) {
                if (strcmp(receiver_login->valuestring, login) == 0) {
                    int64_t created_at_ms = (int64_t)created_at->valuedouble;
                    if (current_time_ms - created_at_ms <= 600000) {
                        mail_panda::Message response;
                        response.set_content(message->valuestring);
                        writer->Write(response);
                    }
                }
            }
            cJSON_Delete(json);
        } else {
            fprintf(stderr, "Ошибка чтения сообщения: %s\n", rd_kafka_err2str(msg->err));
        }
        rd_kafka_message_destroy(msg);
    }
    cleanup(rk);
}

class MailPandaService final : public mail_panda::MailPandaService::Service {
  grpc::Status GetMessagesByToken(grpc::ServerContext* context, const mail_panda::TokenRequest* request,
                                  grpc::ServerWriter<mail_panda::Message>* writer) override {
    char login[MAX_LEN + 1] = {0};
    if (decrypt_token(request->token_hex().c_str(), login) < 0) {
      return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Некорректный токен");
    }

    get_messages(login, writer);
    return grpc::Status::OK;
  }
};

int main() {
    if (sodium_init() < 0) {
        fprintf(stderr, "Ошибка инициализации Libsodium\n");
        return 1;
    }

    std::string server_address("0.0.0.0:50051");
    MailPandaService service;
    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
    printf("gRPC server listening on %s\n", server_address.c_str());
    server->Wait();
    return 0;
}
