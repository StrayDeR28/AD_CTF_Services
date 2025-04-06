from Crypto.Cipher import ChaCha20

# Фиксированный ключ: "The quick brown fox jumps over lazy" (32 байта)
KEY = bytes([
    0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63,
    0x6B, 0x20, 0x62, 0x72, 0x6F, 0x77, 0x6E, 0x20,
    0x66, 0x6F, 0x78, 0x20, 0x6A, 0x75, 0x6D, 0x70,
    0x73, 0x20, 0x6F, 0x76, 0x65, 0x72, 0x20, 0x6C
])

# Фиксированный nonce: все байты нулевые (8 байт для PyCryptodome ChaCha20)
NONCE = b'\x00' * 8  # PyCryptodome использует 8-байтовый nonce для ChaCha20

def generate_token(login):
    plaintext = f"{login}".encode('utf-8')
    cipher = ChaCha20.new(key=KEY, nonce=NONCE)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext.hex()

def decrypt_token(token):
    try:
        ciphertext = bytes.fromhex(token)
        cipher = ChaCha20.new(key=KEY, nonce=NONCE)
        plaintext = cipher.decrypt(ciphertext)
        login = plaintext.decode('utf-8')
        return login
    except Exception as e:
        raise ValueError(f"Ошибка расшифровки токена: {str(e)}")

# Генерируем токен
logins = ['artem', 'lexa', 'dfs']
for login in logins:
    token = generate_token(login)

    print(f"Базовый логин: {login} {len(login)}")
    print(f"Сгенерированный токен: {token} {type(token)} {len(token)}")

    # Расшифровываем токен
    try:
        decrypted_login = decrypt_token(token)
        print(f"Расшифрованный login: {decrypted_login} {len(login)}")
    except ValueError as e:
        print(e)