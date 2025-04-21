from confluent_kafka import Producer, Consumer, KafkaError
from confluent_kafka.admin import AdminClient, NewTopic
import time

# Конфигурация для подключения к Redpanda
BROKER = "localhost:9092"

# Функция создания топика
def create_topic(login, num_partitions=1):
    admin_client = AdminClient({"bootstrap.servers": BROKER})
    
    # Определяем новый топик
    new_topic = NewTopic(
        topic=login,            # Имя топика = логин пользователя
        num_partitions=num_partitions,  # Количество партиций
        replication_factor=1    # Фактор репликации (1 для локального сервера)
    )
    
    # Создаём топик
    fs = admin_client.create_topics([new_topic])
    
    # Ждём завершения создания
    for topic, f in fs.items():
        try:
            f.result()  # Блокируем, пока топик не создастся
            print(f"Топик '{topic}' создан с {num_partitions} партициями")
        except Exception as e:
            print(f"Ошибка создания топика '{topic}': {e}")

# Функция отправки сообщений
def send_messages(login, messages):
    producer = Producer({"bootstrap.servers": BROKER})
    
    def delivery_report(err, msg):
        """Callback для отчёта о доставке"""
        if err is not None:
            print(f"Ошибка доставки: {err}")
        else:
            print(f"Сообщение доставлено в {msg.topic()} [партиция {msg.partition()}]")

    # Отправляем сообщения
    for message in messages:
        producer.produce(
            topic=login,
            value=message.encode("utf-8"),  # Сообщение как байты
            callback=delivery_report
        )
        producer.poll(0)  # Обрабатываем события доставки
    
    # Ждём, пока все сообщения отправятся
    producer.flush()
    print(f"Отправлено {len(messages)} сообщений в топик '{login}'")

# Пример использования
def main():
    # nc localhost 31337
    # Пример логина пользователя AD59577F
    login = "Ivan"
    
    # Создаём топик с 1 партицией
    create_topic(login, num_partitions=1)
    
    # Генерируем пример сообщений (20,000 штук)
    messages = [f"Событие #{i} для {login}" for i in range(1, 14)]
    
    # Отправляем сообщения
    start_time = time.time()
    send_messages(login, messages)
    end_time = time.time()
    
    print(f"Время отправки: {end_time - start_time:.2f} секунд")

    # # (Опционально) Проверка чтения сообщений
    # consumer = Consumer({
    #     "bootstrap.servers": BROKER,
    #     "group.id": "test-group",
    #     "auto.offset.reset": "earliest"
    # })
    # consumer.subscribe([login])
    
    # print("Читаем несколько сообщений для проверки:")
    # for _ in range(5):  # Читаем первые 5 сообщений
    #     msg = consumer.poll(1.0)
    #     if msg is None:
    #         print("Сообщений больше нет")
    #         break
    #     if msg.error():
    #         print(f"Ошибка: {msg.error()}")
    #         break
    #     print(f"Получено: {msg.value().decode('utf-8')}")
    
    # consumer.close()

if __name__ == "__main__":
    main()
