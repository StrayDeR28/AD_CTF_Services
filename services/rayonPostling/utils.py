import random
import hashlib
import time
from Crypto.Cipher import ChaCha20
from confluent_kafka import Producer, KafkaException
import json

BROKER = "redpanda:9092"  # Вместо localhost используем имя сервиса из docker-compose
TOPIC = "user-messages"   # Единый топик

def ImgEncrypt(img, message):
    # Преобразуем строку в байты, затем в битовую строку (без '0b')
    message_bytes = message.encode()  # Работает и с текстом, и с hex-строками
    binMsg = bin(int.from_bytes(message_bytes, "big"))[2:]  # Убираем '0b'
    
    # Дополняем нулями до полных байтов (чтобы len(binMsg) делился на 8)
    binMsg = binMsg.zfill(8 * ((len(binMsg) + 7) // 8))
    
    lenBits = len(binMsg) + 1  # +1 для первого бита
    width = img.size[0]
    height = img.size[1]
    _h = int(height / 2)
    _w = int(width / 2)

    pix = img.load()

    count = 0  # Индекс текущего бита в binMsg
    a0 = pix[_w, _h][0]  # red
    b0 = pix[_w, _h][1]  # green
    c0 = pix[_w, _h][2]  # blue

    # Обрабатываем первый бит
    if count < lenBits - 1:  # -1, т.к. lenBits = len(binMsg) + 1
        if binMsg[count] == "1":
            if (b0 % 2) == 0:
                pix[_w, _h] = (a0, b0 + 1, c0)
        else:
            if (b0 % 2) == 1:
                if b0 == 255:
                    pix[_w, _h] = (a0, 254, c0)
                else:
                    pix[_w, _h] = (a0, b0 + 1, c0)
        count += 1

    _w = _w + 1
    while _h < height:
        for i in range(_w, width):
            if count >= lenBits - 1:
                break

            a = pix[i, _h][0]  # red
            b = pix[i, _h][1]  # green
            c = pix[i, _h][2]  # blue

            if binMsg[count] == "1":
                if (b % 2) == 0:
                    pix[i, _h] = (a, b + 1, c)
            else:
                if (b % 2) == 1:
                    if b == 255:
                        pix[i, _h] = (a, 254, c)
                    else:
                        pix[i, _h] = (a, b + 1, c)
            count += 1

        if count < lenBits - 1:
            _h = _h + 1
            _w = 0
        else:
            break

    return img

# отправка сообщений в топик
def send_messages(receiver_login: str, message: str):
    producer = Producer({"bootstrap.servers": BROKER})

    def delivery_report(err, msg):
        if err is not None:
            print(f"[!] Ошибка доставки сообщения: {err}")
        else:
            print(f"[+] Сообщение доставлено в {msg.topic()} [{msg.partition()}] offset {msg.offset()}")

    # Формируем сообщение в формате JSON
    message_data = {
        "receiver_login": receiver_login,
        "message": message,
        "created_at": int(time.time() * 1000)  # Время создания в миллисекундах
    }

    try:
        producer.produce(
            topic=TOPIC,
            value=json.dumps(message_data).encode("utf-8"),
            callback=delivery_report
        )
        producer.flush()
    except KafkaException as e:
        print(f"[!] Ошибка Kafka: {e}")
    except Exception as e:
        print(f"[!] Неожиданная ошибка: {e}")

# Вспомогательные функции
def generate_signature():
    adjectives = [
        "Великолепный",
        "Удивительный",
        "Невероятный",
        "Фантастический",
        "Волшебный",
    ]
    nouns = ["Друг", "Творец", "Художник", "Писатель", "Мечтатель"]
    
    # Получаем текущее время и хешируем
    now = str(time.time()).encode()
    hash_suffix = hashlib.sha256(now).hexdigest()[:6].upper()  # первые 6 символов хеша

    return f"{random.choice(adjectives)} {random.choice(nouns)} #{hash_suffix}"


def generate_famous_signature():
    famous_signatures = [
        "Микеланджело",
        "Рафаэль",
        "Айвазовский",
        "Леонардо да Винчи",
        "Ван Гог",
        "Пикассо",
        "Дали",
        "Рембрандт",
        "Моне",
        "Кандинский",
    ]
    return random.choice(famous_signatures)


def generate_token(login):
    KEY = bytes(
        [
            0x54,
            0x68,
            0x65,
            0x20,
            0x71,
            0x75,
            0x69,
            0x63,
            0x6B,
            0x20,
            0x62,
            0x72,
            0x6F,
            0x77,
            0x6E,
            0x20,
            0x66,
            0x6F,
            0x78,
            0x20,
            0x6A,
            0x75,
            0x6D,
            0x70,
            0x73,
            0x20,
            0x6F,
            0x76,
            0x65,
            0x72,
            0x20,
            0x70,#0x6C,
        ]
    )

    NONCE = b"\x00" * 8

    plaintext = f"{login}".encode("utf-8")
    cipher = ChaCha20.new(key=KEY, nonce=NONCE)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext.hex()