from confluent_kafka import Consumer, TopicPartition, KafkaError
import time

# Настройки потребителя
conf = {
    'bootstrap.servers': 'localhost:9092',
    'group.id': 'notification-group',
    'auto.offset.reset': 'earliest'  # Сначала читаем старые сообщения
}

# Создаём потребителя
consumer = Consumer(conf)

# Топик, который будем читать
topic = 'notifications'

# Подписываемся на топик
consumer.subscribe([topic])

# Время 10 минут назад (в миллисекундах)
ten_minutes_ago = int((time.time() - 10 * 60) * 1000)

# Получаем метаданные о топике
metadata = consumer.list_topics(topic)
if topic not in metadata.topics:
    print(f"Топик '{topic}' не существует")
    consumer.close()
    exit(1)

# Получаем партиции топика
partitions = [TopicPartition(topic, p) for p in metadata.topics[topic].partitions.keys()]

# Задаём временную метку для поиска смещений (10 минут назад)
for tp in partitions:
    tp.timestamp = ten_minutes_ago

# Получаем смещения для времени 10 минут назад
offsets = consumer.offsets_for_times(partitions)

# Устанавливаем начальные смещения для чтения
consumer.assign(offsets)

print("Сообщения за последние 10 минут:")
found_messages = False

# Читаем сообщения до текущего момента
while True:
    msg = consumer.poll(1.0)
    if msg is None:
        break  # Дошли до конца старых сообщений
    if msg.error():
        if msg.error().code() == KafkaError._PARTITION_EOF:
            break  # Дошли до конца партиции
        else:
            print(f"Ошибка: {msg.error()}")
            consumer.close()
            exit(1)
    # Выводим сообщение с временной меткой
    timestamp = msg.timestamp()[1]  # [type, timestamp]
    print(f"[{time.ctime(timestamp / 1000)}] {msg.value().decode('utf-8')}")
    found_messages = True

if not found_messages:
    print("Сообщений за последние 10 минут нет")

# Переключаемся на режим ожидания новых сообщений
consumer.subscribe([topic])  # Повторная подписка сбрасывает смещения
conf['auto.offset.reset'] = 'latest'  # Теперь только новые сообщения
consumer = Consumer(conf)  # Пересоздаём потребителя для применения 'latest'
consumer.subscribe([topic])

print("\nОжидаю новые сообщения...")
try:
    while True:
        msg = consumer.poll(1.0)
        if msg and not msg.error():
            timestamp = msg.timestamp()[1]
            print(f"[{time.ctime(timestamp / 1000)}] {msg.value().decode('utf-8')}")
except KeyboardInterrupt:
    print("Остановлено пользователем")

finally:
    consumer.close()