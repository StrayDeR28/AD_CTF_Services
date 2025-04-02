#include <sodium.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <libpq-fe.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <netinet/tcp.h>  // Для TCP_NODELAY
#include <stdarg.h>  

#define MAX_LEN 64
#define KEY_SIZE crypto_stream_chacha20_KEYBYTES
#define NONCE_SIZE crypto_stream_chacha20_NONCEBYTES

// Фиксированный nonce (все нули)
static const uint8_t nonce[NONCE_SIZE] = {0};

// Фиксированный ключ (произвольное значение)
// The quick brown fox jumps over lazy
static const uint8_t key[32] = {
    0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63,
    0x6B, 0x20, 0x62, 0x72, 0x6F, 0x77, 0x6E, 0x20,
    0x66, 0x6F, 0x78, 0x20, 0x6A, 0x75, 0x6D, 0x70,
    0x73, 0x20, 0x6F, 0x76, 0x65, 0x72, 0x20, 0x6C
};

// Функции шифрования/расшифровки 
// потом убрать зашифровку, здесь она ни к чему
void encrypt(const uint8_t *plaintext, uint8_t *ciphertext, size_t len, const uint8_t *key) {
    crypto_stream_chacha20_xor(ciphertext, plaintext, len, nonce, key);
}

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
    for (size_t i = 0; i < hex_len / 2; i++) {
        sscanf(hex + (i * 2), "%2hhx", &bin[i]);
    }
    return hex_len / 2;
}

// Подключение к базе данных ******************* нужны параметры от базы данных
PGconn* connect_db() {
    const char *conninfo = "dbname=service user=postgres password=artem host=localhost port=5432";
    PGconn *conn = PQconnectdb(conninfo);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "Ошибка подключения: %s\n", PQerrorMessage(conn));
        PQfinish(conn);
        return NULL;
    }
    return conn;
}

// Получение последней показанной записи
void get_last_seen(PGconn *conn, const char *login, int *last_friend_id, int *last_postcard_id) {
    char query[256];
    snprintf(query, sizeof(query), "SELECT last_friend_id, last_postcard_id FROM user_last_seen WHERE login = '%s'", login);
    PGresult *res = PQexec(conn, query);
    if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
        *last_friend_id = atoi(PQgetvalue(res, 0, 0));
        *last_postcard_id = atoi(PQgetvalue(res, 0, 1));
    } else {    // Если записи нет, создаем новую
        *last_friend_id = 0;
        *last_postcard_id = 0;
        snprintf(query, sizeof(query), "INSERT INTO user_last_seen (login, last_friend_id, last_postcard_id) VALUES ('%s', 0, 0) ON CONFLICT DO NOTHING", login);
        PQexec(conn, query);
    }
    PQclear(res);
}

// Обновление последней показанной записи
void update_last_seen(PGconn *conn, const char *login, int last_friend_id, int last_postcard_id) {
    char query[256];
    snprintf(query, sizeof(query), 
             "INSERT INTO user_last_seen (login, last_friend_id, last_postcard_id) VALUES ('%s', %d, %d) "
             "ON CONFLICT (login) DO UPDATE SET last_friend_id = %d, last_postcard_id = %d",
             login, last_friend_id, last_postcard_id, last_friend_id, last_postcard_id);
    PGresult *res = PQexec(conn, query);
    PQclear(res);
}

// Убирает пробелы с конца строки
void trim(char *str) {
    size_t len = strlen(str);
    while (len > 0 && (str[len - 1] == ' ' || str[len - 1] == '\0')) {
        str[len - 1] = '\0';
        len--;
    }
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
void check_new_records(PGconn *conn, const char *login, int client_fd) {
    int last_friend_id, last_postcard_id;
    get_last_seen(conn, login, &last_friend_id, &last_postcard_id);

    char query[512], response[1024];
    // Запросы в друзья
    snprintf(query, sizeof(query), 
             "SELECT id, friend1_login FROM friends WHERE friend2_login = '%s' AND id > %d ORDER BY id",
             login, last_friend_id);
    PGresult *res = PQexec(conn, query);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        snprintf(response, sizeof(response), "Ошибка базы данных (friends): %s\n", PQerrorMessage(conn));
        send(client_fd, response, strlen(response), 0);

        // printf("Отправка клиенту %d: %s", client_fd, response);
        PQclear(res);
        return;
    }

    int rows = PQntuples(res);
    for (int i = 0; i < rows; i++) {
        char friend1_login[MAX_LEN + 1];
        strncpy(friend1_login, PQgetvalue(res, i, 1), MAX_LEN);
        friend1_login[MAX_LEN] = '\0';
        trim(friend1_login);
        snprintf(response, sizeof(response), "Пришел запрос в друзья от %s\n", friend1_login);
        send(client_fd, response, strlen(response), 0);
        
        // printf("Отправка клиенту %d: %s", client_fd, response);
    }
    if (rows > 0) last_friend_id = atoi(PQgetvalue(res, rows - 1, 0));  // Последний id, если есть записи
    PQclear(res);

    // Сообщения
    snprintf(query, sizeof(query), 
             "SELECT id, sender_login, text FROM postcards WHERE receiver_login = '%s' AND id > %d ORDER BY id",
             login, last_postcard_id);
    res = PQexec(conn, query);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        snprintf(response, sizeof(response), "Ошибка базы данных (postcards): %s\n", PQerrorMessage(conn));
        send(client_fd, response, strlen(response), 0);

        // printf("Отправка клиенту %d: %s", client_fd, response);
        PQclear(res);
        return;
    }

    rows = PQntuples(res);
    for (int i = 0; i < rows; i++) {
        char sender_login[MAX_LEN + 1];
        char text[256 + 1];
        strncpy(sender_login, PQgetvalue(res, i, 1), MAX_LEN);
        sender_login[MAX_LEN] = '\0';
        trim(sender_login);
        strncpy(text, PQgetvalue(res, i, 2), 256);
        text[256] = '\0';
        trim(text);
        snprintf(response, sizeof(response), "Сообщение от %s: %s\n", sender_login, text);
        send(client_fd, response, strlen(response), 0);

        // printf("Отправка клиенту %d: %s", client_fd, response);
    }
    if (rows > 0) last_postcard_id = atoi(PQgetvalue(res, rows - 1, 0));  // Последний id, если есть записи
    PQclear(res);

    update_last_seen(conn, login, last_friend_id, last_postcard_id);
}

void* handle_client(void *arg) {
    int client_fd = (int)(intptr_t)arg;

    PGconn *conn = connect_db();
    if (!conn) {
        send_response(client_fd, "Не удалось подключиться к базе данных\n");
        close(client_fd);
        pthread_exit(NULL);
    }

    send_response(client_fd, "Введите токен (HEX): ");
  
    char buffer[MAX_LEN * 2 + 1] = {0};
    int bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received <= 0) {
        send_response(client_fd, "Ошибка ввода токена\n");
        PQfinish(conn);
        close(client_fd);
        pthread_exit(NULL);
    }

    if (buffer[bytes_received - 1] == '\n') buffer[bytes_received - 1] = '\0';

    // Проверка на валидность HEX-строки
    for (int i = 0; buffer[i] != '\0'; i++) {
        char c = buffer[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            send_response(client_fd, "Токен должен содержать только HEX-символы (0-9, a-f, A-F)\n");
            PQfinish(conn);
            close(client_fd);
            pthread_exit(NULL);
        }
    }

    uint8_t encrypted[MAX_LEN] = {0};
    int encrypted_len = hex_to_bin(buffer, encrypted, MAX_LEN);
    if (encrypted_len < 0) {
        send_response(client_fd, "Некорректный токен\n");
        PQfinish(conn);
        close(client_fd);
        pthread_exit(NULL);
    }

    uint8_t login[MAX_LEN] = {0};
    decrypt(encrypted, login, encrypted_len, key);
    login[encrypted_len] = '\0';

    // Проверка на ASCII или кириллицу
    if (!is_valid_ascii_or_cyrillic((char*)login)) {
        send_response(client_fd, "Токен привёл к некорректному логину (допустимы только ASCII и кириллица)\n");
        PQfinish(conn);
        close(client_fd);
        pthread_exit(NULL);
    }

    send_response(client_fd, "Логин: %s\n", login);

    // Подписываемся на уведомления для этого логина
    char listen_query[256];
    snprintf(listen_query, sizeof(listen_query), "LISTEN new_friend; LISTEN new_postcard;");
    PGresult *res = PQexec(conn, listen_query);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        send_response(client_fd, "Ошибка подписки на уведомления: %s\n", PQerrorMessage(conn));
        PQclear(res);
        PQfinish(conn);
        close(client_fd);
        pthread_exit(NULL);
    }
    PQclear(res);

    // Обрабатываем существующие записи
    check_new_records(conn, (char*)login, client_fd);

    if (PQsetnonblocking(conn, 1) == -1) {
        send_response(client_fd, "Ошибка установки асинхронного режима: %s\n", PQerrorMessage(conn));
        PQfinish(conn);
        close(client_fd);
        pthread_exit(NULL);
    }

    // Основной цикл с уведомлениями
    while (1) {
        PQconsumeInput(conn);  // Получаем данные из сокета базы
        PGnotify *notify = PQnotifies(conn);

        if (notify) {
            // Проверяем, относится ли уведомление к этому логину
            if (strcmp(notify->relname, "new_friend") == 0 && strcmp(notify->extra, login) == 0) {
                check_new_records(conn, (char*)login, client_fd);
            } else if (strcmp(notify->relname, "new_postcard") == 0 && strcmp(notify->extra, login) == 0) {
                check_new_records(conn, (char*)login, client_fd);
            }
            free(notify);
        } else {
            usleep(100000);  // 0.1 секунда, чтобы не нагружать CPU
        }

        char buf[1];
        if (recv(client_fd, buf, 1, MSG_PEEK | MSG_DONTWAIT) == 0) {
            //printf("Клиент %d отключился\n", client_fd);
            PQfinish(conn);
            close(client_fd);
            pthread_exit(NULL);
        }
    }

    PQfinish(conn);
    close(client_fd);  // Никогда не достигается из-за бесконечного цикла
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

    struct sockaddr_in address = {0};   //localhost
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(31337);    //port

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Ошибка bind");
        return 1;
    }

    if (listen(server_fd, 50) < 0) {  // Очередь до 50 клиентов
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

        // Отключаем Nagle's algorithm
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