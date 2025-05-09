#include <sodium.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <librdkafka/rdkafka.h>
#include <time.h> 
#include <cjson/cJSON.h>

#define MAX_LEN 64
#define KEY_SIZE crypto_stream_chacha20_KEYBYTES
#define NONCE_SIZE crypto_stream_chacha20_NONCEBYTES
#define POLL_TIMEOUT_MS 1000 // Тайм-аут в миллисекундах
#define TOPIC "user-messages"
#define BROKER "redpanda:9092"

// The quick brown fox jumps over l ..(azy)
static const uint8_t nonce[NONCE_SIZE] = {0};
static const uint8_t key[KEY_SIZE] = {
    0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63,
    0x6B, 0x20, 0x62, 0x72, 0x6F, 0x77, 0x6E, 0x20,
    0x66, 0x6F, 0x78, 0x20, 0x6A, 0x75, 0x6D, 0x70,
    0x73, 0x20, 0x6F, 0x76, 0x65, 0x72, 0x20, 0x6C
};

char login[MAX_LEN + 1] = {0};

// Отключение буферизации
#define disable_buffering(_fd) setvbuf(_fd, NULL, _IONBF, 0)

// Функция расшифровки
void decrypt(const uint8_t *ciphertext, uint8_t *plaintext, size_t len, const uint8_t *nonce, const uint8_t *key) {
    crypto_stream_chacha20_xor(plaintext, ciphertext, len, nonce, key);
}

// Перевод строки из hex
int hex_to_bin(const char *hex, uint8_t *bin, size_t bin_size) {
    size_t hex_len = strlen(hex);
    if (hex_len > 0 && hex[hex_len - 1] == '\n') hex_len--;
    if (hex_len > 0 && hex[hex_len - 1] == '\r') hex_len--; // Удаляем \r
    if (hex_len % 2 != 0 || hex_len / 2 > bin_size) return -1;
    for (size_t i = 0; i < hex_len / 2; i++) sscanf(hex + (i * 2), "%2hhx", &bin[i]);
    return hex_len / 2;
}

// Чтение строки до \n или \r\n
int read_answ(int fd, char* buf, int size) {
    int i;
    char ch;
    for (i = 0; i < size - 1; i++) { // while (1) {
        if (read(fd, &ch, 1) != 1) break;
        if (ch == '\n') break;
        if (ch == '\r') {
            // Проверяем, есть ли \n после \r
            char next_ch;
            if (read(fd, &next_ch, 1) != 1 || next_ch != '\n') {
                // Если нет \n, это ошибка
                break;
            }
            break;
        }
        buf[i] = ch;
    }
    buf[i] = 0;
    return i;
}

// Очистка ресурсов
void cleanup(rd_kafka_t *rk) {
    if (rk) {
        rd_kafka_consumer_close(rk);
        rd_kafka_destroy(rk);
    }
    // exit(0);
}

// Создание и настройка Kafka-потребителя
rd_kafka_t *create_consumer(const char *group_id, const char *offset_reset) {
    rd_kafka_conf_t *conf = rd_kafka_conf_new();
    char errstr[512];
    
    // Устанавливаем базовые параметры соединения
    rd_kafka_conf_set(conf, "bootstrap.servers", BROKER, errstr, sizeof(errstr));
    rd_kafka_conf_set(conf, "log_level", "3", errstr, sizeof(errstr)); // Уровень INFO
    // rd_kafka_conf_set(conf, "debug", NULL, errstr, sizeof(errstr));     // Отключаем отладку "all"
    rd_kafka_conf_set(conf, "group.id", group_id, errstr, sizeof(errstr));
    rd_kafka_conf_set(conf, "auto.offset.reset", offset_reset, errstr, sizeof(errstr));

    // Создаём потребителя
    rd_kafka_t *rk = rd_kafka_new(RD_KAFKA_CONSUMER, conf, errstr, sizeof(errstr));
    if (!rk) {
        printf("Ошибка создания Kafka-потребителя: %s\n", errstr);
        cleanup(NULL);
    }
    return rk;
}

// Подписка на топик
void subscribe_to_topic(rd_kafka_t *rk, const char *topic) {
    rd_kafka_topic_partition_list_t *topics = rd_kafka_topic_partition_list_new(1);
    rd_kafka_topic_partition_list_add(topics, (char *)topic, RD_KAFKA_PARTITION_UA);
    if (rd_kafka_subscribe(rk, topics) != RD_KAFKA_RESP_ERR_NO_ERROR) {
        printf("Ошибка подписки на топик %s\n", topic);
        rd_kafka_topic_partition_list_destroy(topics);
        cleanup(rk);
        return;
    }
    rd_kafka_topic_partition_list_destroy(topics);
}

// Чтение сообщений за последние 10 минут
void get_messages() {
    rd_kafka_t *rk = create_consumer(login, "earliest");

    // Подписываем потребителя на топик
    subscribe_to_topic(rk, TOPIC);

    // Время 10 минут назад
    int64_t current_time_ms = (int64_t)time(NULL) * 1000;

    printf("Сообщения за последние 10 минут для %s:\n", login);

    while (1) {
        rd_kafka_message_t *msg = rd_kafka_consumer_poll(rk, POLL_TIMEOUT_MS);
        if (!msg) break;
        if (msg->err == RD_KAFKA_RESP_ERR__PARTITION_EOF) {
            rd_kafka_message_destroy(msg);
            break;
        }
        if (msg->err == RD_KAFKA_RESP_ERR_NO_ERROR) {
            char *payload = (char *)msg->payload;
            cJSON *json = cJSON_Parse(payload);
            if (!json) {
                printf("Ошибка парсинга JSON: %s\n", cJSON_GetErrorPtr());
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
                        printf("%s\n", message->valuestring);
                    }
                }
            }

            cJSON_Delete(json);
        } else {
            printf("Ошибка чтения сообщения: %s\n", rd_kafka_err2str(msg->err));
        }
        rd_kafka_message_destroy(msg);
    }
    
    //очистка
    cleanup(rk);
}

// Ввод и расшифровка токена
void input_token() {
    printf("Введите токен (HEX):\n");
    char buffer[128] = {0};
    read_answ(STDIN_FILENO, buffer, sizeof(buffer) - 1);

    uint8_t encrypted[MAX_LEN] = {0};
    int encrypted_len = hex_to_bin(buffer, encrypted, MAX_LEN);
    if (encrypted_len < 0) {
        printf("Некорректный токен\n");
        exit(1);
    }

    decrypt(encrypted, (uint8_t*)login, encrypted_len, nonce, key);
    login[encrypted_len] = '\0';

    printf("Логин: %s\n", login);
}

// Меню
void menu() {
    char buf[4];
    while (1) {
        printf("\nMenu:\n     1.Get messages (last 10 minutes)\n     2.Exit\n");
        read_answ(STDIN_FILENO, buf, sizeof(buf) - 1);
        switch (atoi(buf)) {
            case 1:
                get_messages();
                break;
            case 2:
                printf("Goodbye\n");
                exit(0);
            default:
                printf("Wrong value!\n");
        }
    }
}

int main() {
    if (sodium_init() < 0) {
        printf("Ошибка инициализации Libsodium\n");
        return 1;
    }

    disable_buffering(stdin);
    disable_buffering(stdout);
    disable_buffering(stderr);

    input_token();
    menu();
    return 0;
}