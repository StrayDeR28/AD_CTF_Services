from confluent_kafka import Producer
from confluent_kafka.admin import AdminClient, NewTopic

BROKER = "localhost:9092"

# Функция создания топика
def create_topic(login):
    admin_client = AdminClient({"bootstrap.servers": BROKER})
    new_topic = NewTopic(topic=login, num_partitions=1, replication_factor=1)
    admin_client.create_topics([new_topic]).get(login).result()
    print("++")

# Функция отправки сообщений
def send_messages(login, messages):
    producer = Producer({"bootstrap.servers": BROKER})
    for message in messages:
        producer.produce(topic=login, value=message.encode("utf-8"))
    producer.flush()
    print("--")
    
login = "see"
messages = ["Сообщение 1", "Сообщение 2"]

create_topic(login)  # Создаём топик
send_messages(login, messages)  # Отправляем сообщения
