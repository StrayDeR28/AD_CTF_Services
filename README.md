# [Rayon Postling and Pushling](https://docs.google.com/document/d/1mlCi7va9ZJptabR5f_wPbHOmS434_Avf27pHc7lCZLw/edit?tab=t.0)
Сервисы для ad ctf команды "Underdog-и с сыром". 5 курс, 2025 г.

Сервис - web-приложение (*rayon postling*) для создания и пересылки открыток между пользователями. В дополнение к нему бинарный сервис (*rayon pushling*), показывающий уведомления о событиях произошедших с пользователем web-сервиса: 
* Приглашении пользователя в друзья;
* Получение пользователем новой открытки.

Сервисы сильно связаны между собой, с общими флагсторами.

Авторы: [@artemskorypin](https://github.com/artemskorypin), [@StrayDeR28](https://github.com/StrayDeR28), [@nickname838](https://github.com/nickname838), [@NiZoX101](https://github.com/NiZoX101), [@Vladone9](https://github.com/Vladone9)

## Тэги:
* Web service
* Binary service
* Python
* C
* Crypto

## Уязвимости
### Поле ввода фамилии (*logic*)

[Эксплуатация](https://github.com/StrayDeR28/AD_CTF_Services/blob/main/exploits/exploit_surname.py):
* Зарегистрироваться
* Залогиниться
* Получить список пользователей
* Ходим по профилям пользователей и парсим

### Поле для ввода подписи открытки (*Steganography*)

[Эксплуатация](https://github.com/StrayDeR28/AD_CTF_Services/blob/main/exploits/exploit_steganogrphy.py):
* Зарегистрироваться
* Залогиниться
* Добавиться в друзья
* Отправить открытку
* Применить крипту

### Сообщение открытки (*Cryptography, ROP*)

Эксплуатация:

[Вариант 1](https://github.com/StrayDeR28/AD_CTF_Services/blob/main/exploits/exploit_mail.py):
* Зарегистрироваться
* Залогиниться
* Получить список пользователей
* Зная ключ и нонс, получаем токены пользователей
* Подключаемся ко всем уведомлениям
    
[Вариант 2 Роп простой](https://github.com/StrayDeR28/AD_CTF_Services/blob/main/exploits/ROP_attack_easy_read_console.py):
* Зарегистрироваться
* Залогиниться
* Получить список пользователей
* Найти смещение в стеке бинаря
* Найти глобальный адрес логина
* Найти адреса функции чтения, получения сообщений, гаджета
* Формируем нагрузку на переполнение
* Подключаем гаджет
* Передаем параметры на чтение с консоли нужного логина
* Подключаемся к уведомлениям
      
[Вариант 3 Роп сложный](https://github.com/StrayDeR28/AD_CTF_Services/blob/main/exploits/rop_attack_copying_name_in_loop.py):
* Зарегистрироваться
* Залогиниться
* Получить список пользователей
* Найти смещение в стеке бинаря
* Найти глобальный адрес логина
* Найти адреса функции получения сообщений, 3х гаджетов 
* Формируем нагрузку на переполнение
* Подключаем гаджет
* Передаем параметры (0, логин, мусор)
* По частям (8 символов) копируем логин
* Подключаемся к уведомлениям

## Deploy
### Service
```bash
docker compose up --build
```
### Checker

Интерфейс чекера соответствует описанию: https://github.com/cravtos/calendar/tree/main/checkers/calendary. Лучше выставлять время не меньше 30сек.
```bash
export RUNS=150
export SERVICE=all 
./check.py up
./check.py check
./check.py down
```
Для использование [мини жюри](https://github.com/hacker-volodya/mini-checksystem) нужно выставлять таймаут не меньше 20сек.
