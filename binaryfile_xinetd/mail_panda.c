#include <sodium.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <librdkafka/rdkafka.h>
#include <time.h> 

#define MAX_LEN 64
#define KEY_SIZE crypto_stream_chacha20_KEYBYTES
#define NONCE_SIZE crypto_stream_chacha20_NONCEBYTES
#define POLL_TIMEOUT_MS 1000 // Тайм-аут в миллисекундах

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
void decrypt(const uint8_t *ciphertext, uint8_t *plaintext, size_t len) {
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
    for (i = 0; i < size - 1; i++) {
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

    // Получаем адрес брокера из переменной окружения KAFKA_BROKERS
    const char *bootstrap_servers = getenv("KAFKA_BROKERS");
    if (!bootstrap_servers) {
        bootstrap_servers = "127.0.0.1:9092"; // Значение по умолчанию
    }
    
    // Устанавливаем базовые параметры соединения
    rd_kafka_conf_set(conf, "bootstrap.servers", bootstrap_servers, errstr, sizeof(errstr));
    rd_kafka_conf_set(conf, "log_level", "3", errstr, sizeof(errstr)); // Уровень INFO
    rd_kafka_conf_set(conf, "debug", NULL, errstr, sizeof(errstr));     // Отключаем отладку "all"
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
    rd_kafka_topic_partition_list_add(topics, (char*)topic, RD_KAFKA_PARTITION_UA);
    if (rd_kafka_subscribe(rk, topics) != RD_KAFKA_RESP_ERR_NO_ERROR) {
        printf("Ошибка подписки на топик\n");
        rd_kafka_topic_partition_list_destroy(topics);
        cleanup(rk);
        return;
    }
    rd_kafka_topic_partition_list_destroy(topics);
}

// Чтение сообщений за последние 10 минут
void get_messages() {
    rd_kafka_t *rk = create_consumer(login, "earliest");

    // Проверка существования топика
    struct rd_kafka_metadata *metadata;
    if (rd_kafka_metadata(rk, 0, NULL, (const struct rd_kafka_metadata **)&metadata, 1000) != RD_KAFKA_RESP_ERR_NO_ERROR) {
        printf("Ошибка получения метаданных\n");
        cleanup(rk);
        return;
    }
    int topic_exists = 0;
    for (int i = 0; i < metadata->topic_cnt; i++) {
        if (strcmp(metadata->topics[i].topic, (char*)login) == 0) {
            topic_exists = 1;
            break;
        }
    }
    // int partition_count = metadata->topics[0].partition_cnt;//количество партиций в топике
    rd_kafka_metadata_destroy(metadata);

    if (!topic_exists) {
        printf("Топик для логина %s не существует\n", login);
        cleanup(rk);
        return;
    }

    // Подписываем потребителя на топик
    subscribe_to_topic(rk, (char*)login);

    // Время 10 минут назад
    int64_t ten_minutes_ago = (int64_t)(time(NULL) - 10 * 60) * 1000;

    // Устанавливаем смещения для сообщений за последние 10 минут
    // похоже нам 1 патриции по уши, как тольковыйдем в космос 100000 сообщений/сек, так увеличим
    rd_kafka_topic_partition_list_t *offsets = rd_kafka_topic_partition_list_new(1);
    rd_kafka_topic_partition_list_add(offsets, (char*)login, 0)->offset = ten_minutes_ago;
    if (rd_kafka_offsets_for_times(rk, offsets, 5000) != RD_KAFKA_RESP_ERR_NO_ERROR) {
        printf("Ошибка вычисления смещений\n");
        rd_kafka_topic_partition_list_destroy(offsets);
        cleanup(rk);
        return;
    }
    // Устанавливаем потребителю начальные смещения для чтения
    rd_kafka_assign(rk, offsets);
    rd_kafka_topic_partition_list_destroy(offsets);

    printf("Сообщения за последние 10 минут:\n");
    while (1) {
        rd_kafka_message_t *msg = rd_kafka_consumer_poll(rk, 1000);
        if (!msg) break;
        if (msg->err == RD_KAFKA_RESP_ERR__PARTITION_EOF) {
            rd_kafka_message_destroy(msg);
            break;
        }
        if (msg->err == RD_KAFKA_RESP_ERR_NO_ERROR) {
            printf("%.*s\n", (int)msg->len, (char*)msg->payload);
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

    decrypt(encrypted, (uint8_t*)login, encrypted_len);
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
                // fflush(stdout); // Гарантируем отправку сообщения
                // shutdown(STDOUT_FILENO, SHUT_RDWR); // Принудительное завершение соединения
                // close(STDOUT_FILENO);               // Закрываем stdout
                // close(STDIN_FILENO);                // Закрываем stdin
                // close(STDERR_FILENO); // Закрываем stderr
                // usleep(500000); // Увеличиваем задержку до 0.5 секунды
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