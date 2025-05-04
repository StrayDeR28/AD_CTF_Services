#include <sodium.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <hiredis/hiredis.h>
#include <time.h>
#include "cJSON.h"
#include <sys/socket.h>

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
    if (hex_len > 0 && hex[hex_len - 1] == '\r') hex_len--;
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
            char next_ch;
            if (read(fd, &next_ch, 1) != 1 || next_ch != '\n') break;
            break;
        }
        buf[i] = ch;
    }
    buf[i] = 0;
    return i;
}

// Очистка ресурсов
void cleanup(redisContext *rc) {
    if (rc) redisFree(rc);
    exit(0);
}

// Получение накопленных уведомлений за последние 10 минут
void get_notifications() {
    const char *redis_host = getenv("REDIS_HOST");
    if (!redis_host) redis_host = "redis"; // Default to container name
    redisContext *rc = redisConnect(redis_host, 6379);
    
    if (rc == NULL || rc->err) {
        printf("Ошибка подключения к Redis: %s\n", rc ? rc->errstr : "Не удалось выделить память");
        fflush(stdout);  // Убеждаемся, что сообщение выводится
        cleanup(rc);
    }

    // Получаем список ID уведомлений
    redisReply *reply = redisCommand(rc, "LRANGE %s 0 -1", login);
    if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
        printf("Ошибка выполнения команды LRANGE: %s\n", reply ? reply->str : "Нет ответа");
        freeReplyObject(reply);
        cleanup(rc);
    }

    time_t ten_minutes_ago = time(NULL) - 10 * 60;
    int has_messages = 0;

    printf("Уведомления за последние 10 минут:\n");
    for (size_t i = 0; i < reply->elements; i++) {
        char *msg_id = reply->element[i]->str;
        char msg_key[128];
        snprintf(msg_key, sizeof(msg_key), "%s:msg:%s", login, msg_id);

        // Получаем уведомление по ID
        redisReply *msg_reply = redisCommand(rc, "GET %s", msg_key);
        if (msg_reply == NULL || msg_reply->type == REDIS_REPLY_ERROR || msg_reply->type == REDIS_REPLY_NIL) {
            freeReplyObject(msg_reply);
            continue; // Уведомление истекло или ошибка
        }

        // Парсинг JSON с помощью cJSON
        cJSON *json = cJSON_Parse(msg_reply->str);
        if (json != NULL) {
            cJSON *data = cJSON_GetObjectItemCaseSensitive(json, "data");
            cJSON *timestamp = cJSON_GetObjectItemCaseSensitive(json, "timestamp");
            if (cJSON_IsString(data) && cJSON_IsNumber(timestamp)) {
                if (timestamp->valueint >= ten_minutes_ago) {
                    printf("Уведомление: %s\n", data->valuestring);
                    has_messages = 1;
                }
            }
            cJSON_Delete(json);
        }

        freeReplyObject(msg_reply);
    }

    if (!has_messages) {
        printf("Нет уведомлений за последние 10 минут\n");
    }

    freeReplyObject(reply);
    cleanup(rc);
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
    }

    decrypt(encrypted, (uint8_t*)login, encrypted_len);
    login[encrypted_len] = '\0';

    printf("Логин: %s\n", login);
}

// Меню
void menu() {
    char buf[4];
    while (1) {
        printf("\nMenu:\n     1.Get notifications (last 10 minutes)\n     2.Exit\n");
        read_answ(STDIN_FILENO, buf, sizeof(buf) - 1);
        switch (atoi(buf)) {
            case 1:
                get_notifications();
                break;
            case 2:
                printf("Goodbye\n");
                fflush(stdout);
                shutdown(STDOUT_FILENO, SHUT_RDWR);
                close(STDOUT_FILENO);
                close(STDIN_FILENO);
                close(STDERR_FILENO);
                usleep(500000);
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