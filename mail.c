#include <sodium.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define MAX_LEN 64  // Максимальная длина логина
#define KEY_SIZE crypto_stream_chacha20_KEYBYTES  // 32 байта
#define NONCE_SIZE crypto_stream_chacha20_NONCEBYTES  // 8 байт

// Фиксированный nonce (все нули)
static const uint8_t nonce[NONCE_SIZE] = {0};

// Фиксированный ключ (произвольное значение, например, 32 байта)
// The quick brown fox jumps over lazy
static const uint8_t key[32] = {
    0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63,
    0x6B, 0x20, 0x62, 0x72, 0x6F, 0x77, 0x6E, 0x20,
    0x66, 0x6F, 0x78, 0x20, 0x6A, 0x75, 0x6D, 0x70,
    0x73, 0x20, 0x6F, 0x76, 0x65, 0x72, 0x20, 0x6C
};


// Функция шифрования
void encrypt(const uint8_t *plaintext, uint8_t *ciphertext, size_t len, const uint8_t *key) {
    crypto_stream_chacha20_xor(ciphertext, plaintext, len, nonce, key);
}

// Функция расшифровки
void decrypt(const uint8_t *ciphertext, uint8_t *plaintext, size_t len, const uint8_t *key) {
    crypto_stream_chacha20_xor(plaintext, ciphertext, len, nonce, key);
}

// Функция для вывода данных в HEX
void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

// Функция HEX -> uint8_t[]
int hex_to_bin(const char *hex, uint8_t *bin, size_t bin_size) {
    size_t hex_len = strlen(hex);
    if (hex_len > 0 && hex[hex_len - 1] == '\n') {
        hex_len--;
    }
    if (hex_len % 2 != 0 || hex_len / 2 > bin_size) {
        return -1; // Ошибка
    }
    for (size_t i = 0; i < hex_len / 2; i++) {
        sscanf(hex + (i * 2), "%2hhx", &bin[i]);
    }
    return hex_len / 2;
}

int main() {
    if (sodium_init() < 0) {
        printf("Ошибка инициализации Libsodium\n");
        return 1;
    }

    // Ввод логина
    uint8_t login[MAX_LEN] = {0};
    printf("Введите логин (максимум %d символов): ", MAX_LEN - 1);
    if (!fgets((char *)login, MAX_LEN, stdin)) {
        printf("Ошибка ввода\n");
        return 1;
    }

    size_t login_len = strcspn((char *)login, "\n");
    login[login_len] = '\0';

    // Вывод фиксированного ключа и nonce для информации
    printf("Фиксированный ключ (HEX): ");
    print_hex(key, KEY_SIZE);
    printf("Фиксированный nonce (HEX): ");
    print_hex(nonce, NONCE_SIZE);

    // Шифрование
    uint8_t encrypted[MAX_LEN] = {0};
    encrypt(login, encrypted, login_len, key);
    printf("Зашифрованный токен (HEX): ");
    print_hex(encrypted, login_len);

    // Расшифровка
    uint8_t decrypted[MAX_LEN] = {0};
    decrypt(encrypted, decrypted, login_len, key);
    decrypted[login_len] = '\0';
    printf("Расшифрованный логин: %s\n", decrypted);

    // Ввод токена для расшифровки
    uint8_t hex_encrypted[MAX_LEN * 2 + 1];
    printf("\nВведите зашифрованный токен (HEX): ");
    if (!fgets((char *)hex_encrypted, sizeof(hex_encrypted), stdin)) {
        printf("Ошибка ввода\n");
        return 1;
    }

    uint8_t encrypted_2[MAX_LEN] = {0};
    int encrypted_len = hex_to_bin((char *)hex_encrypted, encrypted_2, MAX_LEN);
    if (encrypted_len < 0) {
        printf("Ошибка: некорректный HEX-токен\n");
        return 1;
    }

    uint8_t decrypted_2[MAX_LEN] = {0};
    decrypt(encrypted_2, decrypted_2, encrypted_len, key);
    decrypted_2[encrypted_len] = '\0';
    printf("Расшифрованный логин: %s\n", decrypted_2);

    return 0;
}