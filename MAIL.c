#include <sodium.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>  // Для функции sleep
#include <libpq-fe.h>  // Библиотека PostgreSQL

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
void encrypt(const uint8_t *plaintext, uint8_t *ciphertext, size_t len, const uint8_t *key) {
    crypto_stream_chacha20_xor(ciphertext, plaintext, len, nonce, key);
}

void decrypt(const uint8_t *ciphertext, uint8_t *plaintext, size_t len, const uint8_t *key) {
    crypto_stream_chacha20_xor(plaintext, ciphertext, len, nonce, key);
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
    const char *conninfo = "dbname=your_db user=your_user password=your_password host=localhost port=5432";
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
    } else {
        *last_friend_id = 0;
        *last_postcard_id = 0;
        // Если записи нет, создаем новую
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

// Проверка новых записей
void check_new_records(PGconn *conn, const char *login) {
    int last_friend_id, last_postcard_id;
    get_last_seen(conn, login, &last_friend_id, &last_postcard_id);

    // Запросы в друзья
    char query[512];
    snprintf(query, sizeof(query), 
             "SELECT id, friend1_login FROM friends WHERE friend2_login = '%s' AND id > %d ORDER BY id",
             login, last_friend_id);
    PGresult *res = PQexec(conn, query);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Ошибка запроса: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return;
    }

    int id;
    int rows = PQntuples(res);
    for (int i = 0; i < rows; i++) {
        id = atoi(PQgetvalue(res, i, 0));
        const char *friend1_login = PQgetvalue(res, i, 1);
        printf("Пришел запрос в друзья от %s\n", friend1_login);
        // if (id > last_friend_id) last_friend_id = id;
    }
    last_friend_id = id;
    PQclear(res);

    // Сообщения
    snprintf(query, sizeof(query), 
             "SELECT id, sender_login, text FROM postcards WHERE receiver_login = '%s' AND id > %d ORDER BY id",
             login, last_postcard_id);
    res = PQexec(conn, query);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Ошибка запроса: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return;
    }

    rows = PQntuples(res);
    for (int i = 0; i < rows; i++) {
        id = atoi(PQgetvalue(res, i, 0));
        const char *sender_login = PQgetvalue(res, i, 1);
        const char *text = PQgetvalue(res, i, 2);
        printf("Сообщение от %s: %s\n", sender_login, text);
        // if (id > last_postcard_id) last_postcard_id = id;
    }
    last_postcard_id = id;
    PQclear(res);

    // Обновляем последнюю просмотренную запись
    update_last_seen(conn, login, last_friend_id, last_postcard_id);
}

int main() {
    if (sodium_init() < 0) {
        printf("Ошибка инициализации Libsodium\n");
        return 1;
    }

    // Ввод токена
    uint8_t hex_token[MAX_LEN * 2 + 1];
    printf("Введите токен (HEX): ");
    if (!fgets((char *)hex_token, sizeof(hex_token), stdin)) {
        printf("Ошибка ввода\n");
        return 1;
    }

    // Расшифровка токена
    uint8_t encrypted[MAX_LEN] = {0};
    int encrypted_len = hex_to_bin((char *)hex_token, encrypted, MAX_LEN);
    if (encrypted_len < 0) {
        printf("Ошибка: некорректный HEX-токен\n");
        return 1;
    }

    uint8_t login[MAX_LEN] = {0};
    decrypt(encrypted, login, encrypted_len, key);
    login[encrypted_len] = '\0';
    printf("Расшифрованный логин: %s\n", login);

    // Подключение к базе
    PGconn *conn = connect_db();
    if (!conn) return 1;

    // Проверка новых записей
    check_new_records(conn, (char *)login);

    // Пока пользователь подключен (имитация)
    printf("Ожидание новых записей... (нажмите Ctrl+C для выхода)\n");
    while (1) {
        check_new_records(conn, (char *)login);
        sleep(5);  // Проверка каждые 5 секунд
    }

    PQfinish(conn);
    return 0;
}
