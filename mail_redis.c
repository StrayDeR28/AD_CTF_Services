#include <sodium.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <hiredis/hiredis.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <netinet/tcp.h>
#include <stdarg.h>

#define MAX_LEN 64
#define KEY_SIZE crypto_stream_chacha20_KEYBYTES
#define NONCE_SIZE crypto_stream_chacha20_NONCEBYTES
#define BUFFER_SIZE 4096
#define DB_SERVER_IP "10.0.0.1" // IP центрального сервера в Wireguard
#define DB_SERVER_PORT 5555

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

// перевод строки в hex
int hex_to_bin(const char *hex, uint8_t *bin, size_t bin_size) {
    size_t hex_len = strlen(hex);
    if (hex_len > 0 && hex[hex_len - 1] == '\n') hex_len--;
    if (hex_len % 2 != 0 || hex_len / 2 > bin_size) return -1;
    for (size_t i = 0; i < hex_len / 2; i++) sscanf(hex + (i * 2), "%2hhx", &bin[i]);
    return hex_len / 2;
}

// Функция для отправки запросов к серверу базы
int query_db(const char *sql_template, const char *params[], int param_count, char *response, size_t response_size) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in server_addr = {AF_INET, htons(DB_SERVER_PORT)};
    inet_pton(AF_INET, DB_SERVER_IP, &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sock);
        return -1;
    }

    // Формируем запрос: шаблон|param1|param2|...
    char request[BUFFER_SIZE];
    int offset = snprintf(request, sizeof(request), "%s", sql_template);
    for (int i = 0; i < param_count; i++) {
        offset += snprintf(request + offset, sizeof(request) - offset, "|%s", params[i]);
    }
    send(sock, request, strlen(request), 0);

    int bytes_received = recv(sock, response, response_size - 1, 0);
    if (bytes_received > 0) response[bytes_received] = '\0';

    close(sock);
    return bytes_received > 0 ? 0 : -1;
}

// Получение последней показанной записи
void get_last_seen(const char *login, const char *ip, int *last_friend_id, int *last_postcard_id) {
    const char *sql = "SELECT last_friend_id, last_postcard_id FROM user_last_seen WHERE login = ? AND ip = ?";
    const char *params[] = {login, ip};
    char response[BUFFER_SIZE];

    if (query_db(sql, params, 2, response, sizeof(response)) == 0 && strlen(response) > 0) {
        sscanf(response, "%d|%d", last_friend_id, last_postcard_id);
    } else {
        *last_friend_id = 0;
        *last_postcard_id = 0;
        const char *insert_sql = "INSERT OR IGNORE INTO user_last_seen (login, ip, last_friend_id, last_postcard_id) VALUES (?, ?, ?, ?)";
        const char *insert_params[] = {login, ip, "0", "0"};
        query_db(insert_sql, insert_params, 4, response, sizeof(response));
    }
}

// Обновление последней показанной записи
void update_last_seen(const char *login, const char *ip, int last_friend_id, int last_postcard_id) {
    const char *sql = "INSERT OR REPLACE INTO user_last_seen (login, ip, last_friend_id, last_postcard_id) VALUES (?, ?, ?, ?)";
    char friend_id_str[16], postcard_id_str[16];
    snprintf(friend_id_str, sizeof(friend_id_str), "%d", last_friend_id);
    snprintf(postcard_id_str, sizeof(postcard_id_str), "%d", last_postcard_id);
    const char *params[] = {login, ip, friend_id_str, postcard_id_str};
    char response[BUFFER_SIZE];
    query_db(sql, params, 4, response, sizeof(response));
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

// Проверка новых записей
void check_new_records(const char *login, const char *ip, int client_fd) {
    int last_friend_id, last_postcard_id;
    get_last_seen(login, ip, &last_friend_id, &last_postcard_id);

    char response[BUFFER_SIZE];
    char last_friend_id_str[16], last_postcard_id_str[16];
    snprintf(last_friend_id_str, sizeof(last_friend_id_str), "%d", last_friend_id);
    snprintf(last_postcard_id_str, sizeof(last_postcard_id_str), "%d", last_postcard_id);

    // Проверка friends
    const char *sql_friends = "SELECT id, friend1_login FROM friends WHERE friend2_login = ? AND id > ? ORDER BY id";
    const char *friend_params[] = {login, last_friend_id_str};
    if (query_db(sql_friends, friend_params, 2, response, sizeof(response)) == 0) {
        char *line = strtok(response, "\n");
        while (line) {
            int id;
            char friend1_login[MAX_LEN];
            sscanf(line, "%d|%s", &id, friend1_login);
            send_response(client_fd, "Пришел запрос в друзья от %s\n", friend1_login);
            if (id > last_friend_id) last_friend_id = id;
            line = strtok(NULL, "\n");
        }
    }

    // Проверка postcards
    const char *sql_postcards = "SELECT id, sender_login, text FROM postcards WHERE receiver_login = ? AND id > ? ORDER BY id";
    const char *postcard_params[] = {login, last_postcard_id_str};
    if (query_db(sql_postcards, postcard_params, 2, response, sizeof(response)) == 0) {
        char *line = strtok(response, "\n");
        while (line) {
            int id;
            char sender_login[MAX_LEN], text[256];
            sscanf(line, "%d|%s|%s", &id, sender_login, text);
            send_response(client_fd, "Сообщение от %s: %s\n", sender_login, text);
            if (id > last_postcard_id) last_postcard_id = id;
            line = strtok(NULL, "\n");
        }
    }

    update_last_seen(login, ip, last_friend_id, last_postcard_id);
}

void *handle_client(void *arg) {
    int client_fd = (int)(intptr_t)arg;

    redisContext *redis = redisConnect("localhost", 6379);
    if (redis == NULL || redis->err) {
        send_response(client_fd, "Не удалось подключиться к Redis\n");
        close(client_fd);
        pthread_exit(NULL);
    }

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    if (getpeername(client_fd, (struct sockaddr*)&client_addr, &client_len) < 0) {
        send_response(client_fd, "Ошибка получения IP клиента\n");
        redisFree(redis);
        close(client_fd);
        pthread_exit(NULL);
    }
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, ip, INET_ADDRSTRLEN);

    send_response(client_fd, "Введите токен (HEX): ");
    char buffer[MAX_LEN * 2 + 1] = {0};
    int bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received <= 0) {
        send_response(client_fd, "Ошибка ввода токена\n");
        redisFree(redis);
        close(client_fd);
        pthread_exit(NULL);
    }
    if (buffer[bytes_received - 1] == '\n') buffer[bytes_received - 1] = '\0';

    // Проверка на валидность HEX-строки
    for (int i = 0; buffer[i]; i++) {
        char c = buffer[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            send_response(client_fd, "Токен должен содержать только HEX-символы\n");
            redisFree(redis);
            close(client_fd);
            pthread_exit(NULL);
        }
    }

    uint8_t encrypted[MAX_LEN] = {0};
    int encrypted_len = hex_to_bin(buffer, encrypted, MAX_LEN);
    if (encrypted_len < 0) {
        send_response(client_fd, "Некорректный токен\n");
        redisFree(redis);
        close(client_fd);
        pthread_exit(NULL);
    }

    uint8_t login[MAX_LEN] = {0};
    decrypt(encrypted, login, encrypted_len, key);
    login[encrypted_len] = '\0';

    if (!is_valid_ascii_or_cyrillic((char*)login)) {
        send_response(client_fd, "Токен привёл к некорректному логину\n");
        redisFree(redis);
        close(client_fd);
        pthread_exit(NULL);
    }

    send_response(client_fd, "Логин: %s, IP: %s\n", login, ip);

    // Проверка накопленных записей
    check_new_records((char*)login, ip, client_fd);

    // Подписка на каналы Redis
    char friend_channel[128], message_channel[128];
    snprintf(friend_channel, sizeof(friend_channel), "friend_requests:%s", login);
    snprintf(message_channel, sizeof(message_channel), "friend_messages:%s", login);
    redisCommand(redis, "SUBSCRIBE %s %s", friend_channel, message_channel);

    // Основной цикл обработки уведомлений
    while (1) {
        redisReply *reply;
        if (redisGetReply(redis, (void **)&reply) == REDIS_OK) {
            if (reply->type == REDIS_REPLY_ARRAY && reply->elements == 3) {
                const char *type = reply->element[0]->str;
                if (strcmp(type, "message") == 0) {
                    check_new_records((char*)login, ip, client_fd);
                }
            }
            freeReplyObject(reply);
        }

        // клиент отключился
        char buf[1];
        if (recv(client_fd, buf, 1, MSG_PEEK | MSG_DONTWAIT) == 0) {
            redisFree(redis);
            close(client_fd);
            pthread_exit(NULL);
        }
    }

    redisFree(redis);
    close(client_fd);
    pthread_exit(NULL);
}

int main() {
    signal(SIGPIPE, SIG_IGN);
    if (sodium_init() < 0) {
        printf("Ошибка инициализации Libsodium\n");
        return 1;
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Ошибка создания сокета");
        return 1;
    }

    struct sockaddr_in address = {0}; //localhost
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(31337);    //port

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Ошибка bind");
        return 1;
    }

    if (listen(server_fd, 50) < 0) {
        perror("Ошибка listen");
        return 1;
    }

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("Ошибка accept");
            continue;
        }

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