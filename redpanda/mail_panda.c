#include <sodium.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <netinet/tcp.h>
#include <stdarg.h>
#include <librdkafka/rdkafka.h>

#define MAX_LEN 64
#define KEY_SIZE crypto_stream_chacha20_KEYBYTES
#define NONCE_SIZE crypto_stream_chacha20_NONCEBYTES

// The quick brown fox jumps over l ..(azy)
static const uint8_t nonce[NONCE_SIZE] = {0};
static const uint8_t key[KEY_SIZE] = {
    0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63,
    0x6B, 0x20, 0x62, 0x72, 0x6F, 0x77, 0x6E, 0x20,
    0x66, 0x6F, 0x78, 0x20, 0x6A, 0x75, 0x6D, 0x70,
    0x73, 0x20, 0x6F, 0x76, 0x65, 0x72, 0x20, 0x6C
};

// Функция расшифровки
void decrypt(const uint8_t *ciphertext, uint8_t *plaintext, size_t len, const uint8_t *key) {
    crypto_stream_chacha20_xor(plaintext, ciphertext, len, nonce, key);
}

// Проверка, что строка содержит только ASCII и кириллицу (валидный UTF-8)
int is_valid_ascii_or_cyrillic(const char *str) {
    const unsigned char *s = (const unsigned char *)str;
    while (*s) {
        if (*s >= 0x20 && *s <= 0x7E) {
            // печатные ASCII
            s++;
        } else if (*s == 0xD0 || *s == 0xD1) {
            // Кириллица (U+0400–U+04FF): двухбайтовые символы
            if ((s[1] & 0xC0) != 0x80) return 0;  // Второй байт должен быть 10xxxxxx
            if (*s == 0xD0 && s[1] < 0x90) return 0;  // U+0400–U+041F начинается с 0x90
            if (*s == 0xD1 && s[1] > 0x8F) return 0;  // U+0420–U+04FF заканчивается на 0x8F
            s += 2;
        } else {
            return 0;  // Другие UTF-8 последовательности не допускаем
        }
    }
    return 1;
}

// перевод строки из hex
int hex_to_bin(const char *hex, uint8_t *bin, size_t bin_size) {
    size_t hex_len = strlen(hex);
    if (hex_len > 0 && hex[hex_len - 1] == '\n') hex_len--;
    if (hex_len % 2 != 0 || hex_len / 2 > bin_size) return -1;
    for (size_t i = 0; i < hex_len / 2; i++) sscanf(hex + (i * 2), "%2hhx", &bin[i]);
    return hex_len / 2;
}

//отправка сообщений
static void send_response(int client_fd, const char *format, ...) {
    char response[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(response, sizeof(response), format, args);
    va_end(args);
    send(client_fd, response, strlen(response), 0);
}

// Очистка ресурсов
void cleanup(rd_kafka_t *rk, int client_fd) {
    if (rk) {
        rd_kafka_consumer_close(rk);
        rd_kafka_destroy(rk);
    }
    if (client_fd >= 0) close(client_fd);
    pthread_exit(NULL);
}

// Создание и настройка Kafka-потребителя
rd_kafka_t *create_consumer(const char *group_id, const char *offset_reset, int client_fd) {
    rd_kafka_conf_t *conf = rd_kafka_conf_new();
    char errstr[512];

    // Устанавливаем базовые параметры соединения (куда (докер!), кто, откуда смотрим уведомления (с начала, с конца))
    rd_kafka_conf_set(conf, "bootstrap.servers", "localhost:9092", errstr, sizeof(errstr));
    rd_kafka_conf_set(conf, "group.id", group_id, errstr, sizeof(errstr));
    rd_kafka_conf_set(conf, "auto.offset.reset", offset_reset, errstr, sizeof(errstr));

    // Создаём потребителя
    rd_kafka_t *rk = rd_kafka_new(RD_KAFKA_CONSUMER, conf, errstr, sizeof(errstr));
    if (!rk) {
        send_response(client_fd, "Ошибка создания Kafka-потребителя: %s\n", errstr);
        cleanup(NULL, client_fd);
    }
    return rk;
}

// Подписка на топик
void subscribe_to_topic(rd_kafka_t *rk, const char *topic, int client_fd) {
    rd_kafka_topic_partition_list_t *topics = rd_kafka_topic_partition_list_new(1);
    rd_kafka_topic_partition_list_add(topics, (char*)topic, RD_KAFKA_PARTITION_UA);
    if (rd_kafka_subscribe(rk, topics) != RD_KAFKA_RESP_ERR_NO_ERROR) {
        send_response(client_fd, "Ошибка подписки на топик\n");
        rd_kafka_topic_partition_list_destroy(topics);
        cleanup(rk, client_fd);
    }
    rd_kafka_topic_partition_list_destroy(topics);
}

void *handle_client(void *arg) {
    int client_fd = (int)(intptr_t)arg;

    

    send_response(client_fd, "Введите токен (HEX): ");
    char buffer[MAX_LEN * 2 + 1] = {0};
    int bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received <= 0) {
        send_response(client_fd, "Ошибка ввода токена\n");
        cleanup(NULL, client_fd);
    }
    if (buffer[bytes_received - 1] == '\n') buffer[bytes_received - 1] = '\0';

    // Проверка на валидность HEX-строки
    for (int i = 0; buffer[i]; i++) {
        char c = buffer[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            send_response(client_fd, "Токен должен содержать только HEX-символы\n");
            cleanup(NULL, client_fd);
        }
    }

    uint8_t encrypted[MAX_LEN] = {0};
    int encrypted_len = hex_to_bin(buffer, encrypted, MAX_LEN);
    if (encrypted_len < 0) {
        send_response(client_fd, "Некорректный токен\n");
        cleanup(NULL, client_fd);
    }

    uint8_t login[MAX_LEN + 1] = {0};
    decrypt(encrypted, login, encrypted_len, key);
    login[encrypted_len] = '\0';

    if (!is_valid_ascii_or_cyrillic((char*)login)) {
        send_response(client_fd, "Токен привёл к некорректному логину\n");
        cleanup(NULL, client_fd);
    }

    send_response(client_fd, "Логин: %s\n", login);

   // Создаём первого потребителя для чтения сообщений за последние 10 минут
   rd_kafka_t *rk = create_consumer(login, "earliest", client_fd);

    // Проверка существования топика
    struct rd_kafka_metadata *metadata;
    if (rd_kafka_metadata(rk, 0, NULL, (const struct rd_kafka_metadata **)&metadata, 1000) != RD_KAFKA_RESP_ERR_NO_ERROR) {
        send_response(client_fd, "Ошибка получения метаданных\n");
        cleanup(rk, client_fd);
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
        send_response(client_fd, "Топик для логина %s не существует\n", login);
        cleanup(rk, client_fd);
    }

    // Подписываем первого потребителя на топик
    subscribe_to_topic(rk, (char*)login, client_fd);

    // Время 10 минут назад
    int64_t ten_minutes_ago = (int64_t)(time(NULL) - 10 * 60) * 1000;

    // Устанавливаем смещения для сообщений за последние 10 минут
    // похоже нам 1 патриции по уши, как тольковыйдем в космос 100000 сообщений/сек, так увеличим
    rd_kafka_topic_partition_list_t *offsets = rd_kafka_topic_partition_list_new(1); // partition_count
    rd_kafka_topic_partition_list_add(offsets, (char*)login, 0)->offset = ten_minutes_ago;
    // for (int i = 0; i < partition_count; i++) {
    //     // Для каждой партиции задаём время, с которого хотим начать чтение
    //     rd_kafka_topic_partition_list_add(offsets, (char*)login, i)->offset = ten_minutes_ago;
    // }
    // Запрашиваем у брокера смещения, соответствующие времени 10 минут назад
    if (rd_kafka_offsets_for_times(rk, offsets, 1000) != RD_KAFKA_RESP_ERR_NO_ERROR) {
        send_response(client_fd, "Ошибка вычисления смещений\n");
        rd_kafka_topic_partition_list_destroy(offsets);
        cleanup(rk, client_fd);
    }
    // Устанавливаем потребителю начальные смещения для чтения
    rd_kafka_assign(rk, offsets);
    rd_kafka_topic_partition_list_destroy(offsets);

    send_response(client_fd, "Актуальные сообщения:\n");

    // Читаем сообщения за последние 10 минут
    while (1) {
        rd_kafka_message_t *msg = rd_kafka_consumer_poll(rk, 1000);
        if (!msg) break;
        if (msg->err == RD_KAFKA_RESP_ERR__PARTITION_EOF) {
            rd_kafka_message_destroy(msg);
            break;
        }
        if (msg->err == RD_KAFKA_RESP_ERR_NO_ERROR) {
            send_response(client_fd, "%.*s\n", (int)msg->len, (char*)msg->payload);
        }
        rd_kafka_message_destroy(msg);
    }

    // Закрываем первого потребителя
    rd_kafka_consumer_close(rk);
    rd_kafka_destroy(rk);

    // Создаём второго потребителя для новых сообщений
    rk = create_consumer(login, "latest", client_fd);
    // Подписываем второго потребителя на топик
    subscribe_to_topic(rk, (char*)login, client_fd);

    // Основной цикл для новых сообщений
    while (1) {
        rd_kafka_message_t *msg = rd_kafka_consumer_poll(rk, 1000);
        if (msg) {
            if (msg->err == RD_KAFKA_RESP_ERR_NO_ERROR) {
                send_response(client_fd, "%.*s\n", (int)msg->len, (char*)msg->payload);
            }
            rd_kafka_message_destroy(msg);
        }

        // Проверка отключения клиента ctrl+c
        char buf[1];
        if (recv(client_fd, buf, 1, MSG_PEEK | MSG_DONTWAIT) == 0) {
            cleanup(rk, client_fd);
        }
    }
}

int main() {
    signal(SIGPIPE, SIG_IGN);//ctrl+c от клиента, а мы не падаем
    if (sodium_init() < 0) {// дабы избежать краха перед использованием крипты
        printf("Ошибка инициализации Libsodium\n");
        return 1;
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Ошибка создания сокета");
        return 1;
    }

    //подключение к сервису
    struct sockaddr_in address = {0}; //localhost
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(31337);    //port

    //Привязываем сокет к адресу и порту
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Ошибка bind");
        return 1;
    }

    if (listen(server_fd, 100) < 0) {
        perror("Ошибка listen");
        return 1;
    }

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        //ожидаем нового подключения
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("Ошибка accept");
            continue;
        }

        //чтобы данные отправлялись сразу, иначе могут где-то теряться
        int flag = 1;
        if (setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int)) < 0) {
            perror("Ошибка setsockopt TCP_NODELAY");
            close(client_fd);
            continue;
        }
        // Создаём поток
        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_client, (void*)(intptr_t)client_fd) != 0) {
            perror("Ошибка создания потока");
            close(client_fd);
            continue;
        }
        // Отсоединяем поток, чтобы он очищался автоматически
        pthread_detach(thread);
    }

    close(server_fd);
    return 0;
}