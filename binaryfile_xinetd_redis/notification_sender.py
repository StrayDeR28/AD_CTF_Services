import redis
import json
import time

# Подключение к Redis
r = redis.Redis(host='localhost', port=6379, decode_responses=True)

def send_notification(login, notification_type, data):
    # Формируем уведомление как JSON
    notification = json.dumps({
        "type": notification_type,
        "data": data,
        "timestamp": int(time.time())
    })
    
    # Генерируем уникальный ID для уведомления (timestamp + счетчик)
    msg_id = f"{int(time.time())}:{r.incr(f'{login}:msg_counter')}"
    msg_key = f"{login}:msg:{msg_id}"
    
    # Сохраняем уведомление как отдельный ключ с TTL 10 минут
    r.set(msg_key, notification, ex=600)
    
    # Добавляем ID уведомления в список логина
    r.rpush(login, msg_id)

# Пример использования
if __name__ == "__main__":
    # Отправка запроса в дружбу
    send_notification("2", "friend_request", "user123")
    # Отправка сообщения
    send_notification("2", "message", "Привет!")
    print(f"Уведомления отправлены для логина 2, каждое с TTL 10 минут")