import random
from Crypto.Cipher import ChaCha20
from confluent_kafka import Producer, KafkaException
from confluent_kafka.admin import AdminClient, NewTopic

BROKER = "redpanda:9092"  # Вместо localhost используем имя сервиса из docker-compose


def ImgEncrypt(img, message):
    lenBits = (len(message) * 8) + 1
    width = img.size[0]
    height = img.size[1]
    _h = int(height / 2)
    _w = int(width / 2)

    pix = img.load()

    binMsg = bin(int.from_bytes(message.encode(), "big"))

    count = 2
    a0 = pix[_w, _h][0]  # red
    b0 = pix[_w, _h][1]  # green
    c0 = pix[_w, _h][2]  # blue
    if binMsg[0] == "1":
        if (b0 % 2) == 0:
            pix[_w, _h] = (a0, b0 + 1, c0)

    else:
        if (b0 % 2) == 1:
            if b0 == 255:
                pix[_w, _h] = (a0, 254, c0)
            else:
                pix[_w, _h] = (a0, b0 + 1, c0)

    _w = _w + 1
    while _h < height:
        for i in range(_w, width):
            a = pix[i, _h][0]  # red
            b = pix[i, _h][1]  # green
            c = pix[i, _h][2]  # blue

            if count < lenBits:
                if binMsg[count] == "1":
                    count = count + 1
                    if (b % 2) == 0:
                        pix[i, _h] = (a, b + 1, c)

                else:
                    count = count + 1
                    if (b % 2) == 1:
                        if b == 255:
                            pix[i, _h] = (a, 254, c)
                        else:
                            pix[i, _h] = (a, b + 1, c)

            else:
                i = width
                break

        if count < lenBits:
            _h = _h + 1
            _w = 0
        else:
            _h = height
            break

    return img


# Функция создания топика
def create_topic(login):
    if not login or not isinstance(login, str):
        print("Неверный формат логина для создания топика")
        return False

    admin_client = AdminClient({"bootstrap.servers": BROKER})

    # Получаем метаданные с обработкой ошибок
    try:
        metadata = admin_client.list_topics(timeout=10)
    except KafkaException as e:
        print(f"Ошибка получения списка топиков: {str(e)}")
        return False
    except Exception as e:
        print(f"Неожиданная ошибка при получении метаданных: {str(e)}")
        return False

    if login in metadata.topics:
        print(f"Топик '{login}' уже существует")
        return True

    # Создаем новый топик
    print(f"Создание топика '{login}'...")
    new_topic = NewTopic(topic=login, num_partitions=1, replication_factor=1)

    # Создание топика с обработкой результата
    try:
        futures = admin_client.create_topics([new_topic])
        # Ожидаем завершения для конкретного топика
        # futures[login].result(timeout=10)
        print(f"Топик '{login}' успешно создан")
        return True
    except KafkaException as e:
        print(f"Ошибка создания топика '{login}': {str(e)}")
        return False
    except Exception as e:
        print(f"Неожиданная ошибка при создании топика: {str(e)}")
        return False

    # # Проверяем, есть ли топик с именем login
    # if not (login in metadata.topics):
    #     print(f"Топик '{login}' не существует, создаём...")
    #     new_topic = NewTopic(topic=login, num_partitions=1, replication_factor=1)
    #     admin_client.create_topics([new_topic]).get(login).result()
    # else:
    #     print(f"Топик '{login}' уже существует")
    # # print("++")


# Функция отправки сообщений
def send_messages(login, message):
    # Валидация входных данных
    if not login or not isinstance(login, str):
        print("Неверный формат логина топика")
        return False
    
    if not message or not isinstance(message, str):
        print("Неверный формат сообщения")
        return False
    
    # Сначала проверяем существование топика
    admin_client = AdminClient({"bootstrap.servers": BROKER})
    
    try:
        metadata = admin_client.list_topics(timeout=10)
        if login not in metadata.topics:
            print(f"Топик '{login}' не существует")
            return False
    except KafkaException as e:
        print(f"Ошибка проверки топика '{login}': {str(e)}")
        return False
    except Exception as e:
        print(f"Неожиданная ошибка при проверке топика: {str(e)}")
        return False

    producer = Producer({"bootstrap.servers": BROKER})

    try:
        producer.produce(
            topic=login,
            value=message.encode("utf-8")
        )
        producer.flush(timeout=5)
        print(f"Сообщение успешно отправлено в топик '{login}'")
        return True
    except KafkaException as e:
        print(f"Ошибка отправки сообщения: {str(e)}")
        return False
    except UnicodeEncodeError:
        print("Ошибка кодирования сообщения")
        return False
    except Exception as e:
        print(f"Неожиданная ошибка при отправке: {str(e)}")
        return False

    # # for message in messages:
    # producer.produce(topic=login, value=message.encode("utf-8"))
    # producer.flush()
    # # print("--")


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
    numbers = random.randint(100, 999)
    return f"{random.choice(adjectives)} {random.choice(nouns)} #{numbers}"


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
            0x6C,
        ]
    )

    NONCE = b"\x00" * 8

    plaintext = f"{login}".encode("utf-8")
    cipher = ChaCha20.new(key=KEY, nonce=NONCE)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext.hex()
