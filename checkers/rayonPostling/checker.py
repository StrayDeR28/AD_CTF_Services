#!/usr/bin/env python3

import html
import inspect
import json
import os
import random
import re
import string
import sys
import time
import pickle
from enum import Enum
from sys import argv

import copy
os.environ['PWNLIB_NOTERM'] = '1'
argv = copy.deepcopy(sys.argv)

# юзаем argv

# Make all random more random.
import requests
from faker import Faker
from pwn import *
from bs4 import BeautifulSoup
from PIL import Image
from io import BytesIO
import secrets # входит в питон

context.log_level = 'info' #????

random = random.SystemRandom()

""" <config> """
# SERVICE INFO
PORT = 5000
EXPLOIT_NAME = argv[0]

# DEBUG -- logs to stderr, TRACE -- log HTTP requests
DEBUG = os.getenv("DEBUG", True)
TRACE = os.getenv("TRACE", False)
""" </config> """

class FakeSession(requests.Session):
    """
    FakeSession reference:
        - `s = FakeSession(host, PORT)` -- creation
        - `s` mimics all standard request.Session API except of fe features:
            -- `url` can be started from "/path" and will be expanded to "http://{host}:{PORT}/path"
            -- for non-HTTP scheme use "https://{host}/path" template which will be expanded in the same manner
            -- `s` uses random browser-like User-Agents for every requests
            -- `s` closes connection after every request, so exploit get splitted among multiple TCP sessions
    Short requests reference:
        - `s.post(url, data={"arg": "value"})`          -- send request argument
        - `s.post(url, headers={"X-Boroda": "DA!"})`    -- send additional headers
        - `s.post(url, auth=(login, password)`          -- send basic http auth
        - `s.post(url, timeout=1.1)`                    -- send timeouted request
        - `s.request("CAT", url, data={"eat":"mice"})`  -- send custom-verb request
        (response data)
        - `r.text`/`r.json()`  -- text data // parsed json object
    """

    USER_AGENTS = [
        """Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1 Safari/605.1.15""",
        """Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36""",
        """Mozilla/5.0 (Windows; U; Windows NT 6.1; rv:2.2) Gecko/20110201""",
        """Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.13; ) Gecko/20101203""",
        """Mozilla/5.0 (Windows NT 5.1) Gecko/20100101 Firefox/14.0 Opera/12.0""",
    ]

    def __init__(self, host, port):
        super(FakeSession, self).__init__()
        if port:
            self.host_port = "{}:{}".format(host, port)
        else:
            self.host_port = host

    def prepare_request(self, request):
        r = super(FakeSession, self).prepare_request(request)
        r.headers["User-Agent"] = random.choice(FakeSession.USER_AGENTS)
        r.headers["Connection"] = "close"
        return r

    # fmt: off
    def request(self, method, url,
                params=None, data=None, headers=None,
                cookies=None, files=None, auth=None, timeout=None, allow_redirects=True,
                proxies=None, hooks=None, stream=None, verify=None, cert=None, json=None,
                ):
        if url[0] == "/" and url[1] != "/":
            url = "http://" + self.host_port + url
        else:
            url = url.format(host=self.host_port)
        r = super(FakeSession, self).request(
            method, url, params, data, headers, cookies, files, auth, timeout,
            allow_redirects, proxies, hooks, stream, verify, cert, json,
        )
        if TRACE:
            print("[TRACE] {method} {url} {r.status_code}".format(**locals()))
        return r
    # fmt: on

# Вспомогательные функции
def _gen_user():
    # _log("Generate user")
    faker = Faker()
    name = faker.first_name()
    surname = faker.last_name()
    # base_username = faker.user_name()
    # # Исправление: secrets.token_hex вместо secrets()
    # unique_suffix = f"{secrets.token_hex(4)}_{secrets.token_hex(4)}"
    # username = f"{base_username}_{unique_suffix}"
    password = faker.password(length=12)
    username = faker.user_name()
    
    # _log(f"Generated users data: {username}, {password}, {name}, {surname}")
    return username, password, name, surname

# регистрация
def _register(s, username, password, name, surname):
    # _log(f"Register user. login: {username}, password: {password}, name: {name}, surname: {surname}")
    try:
        r = s.post(
            "/register",
            data={"login": username, "password": password, "name": name, "surname": surname},
            allow_redirects=False,
        )
    except Exception as e:
        _log(f"Failed to register: {e}")
        die(ExitStatus.DOWN, f"Failed to register: {e}")
    
    if r.status_code != 302:
        _log(f"Unexpected /register status code {r.status_code}")
        die(ExitStatus.MUMBLE, f"Unexpected /register status code {r.status_code}")
    if len(r.cookies) == 0:
        _log(f"No cookies set after registration")
        die(ExitStatus.MUMBLE, "No cookies set after registration")
    if r.headers.get("Location") != "/login":
        _log(f"Unexpected redirect after registration: {r.headers.get('Location')}")   #где мы?
        die(ExitStatus.MUMBLE, f"Unexpected redirect after registration: {r.headers.get('Location')}")

# логирование
def _login(s, username, password):
    # _log(f"Login under user: {username}, {password}")
    try:
        r = s.post(
            "/login",
            data={"login": username, "password": password},
            allow_redirects=False,
        )
    except Exception as e:
        die(ExitStatus.DOWN, f"Failed to login: {e}")
    
    if r.status_code != 302:
        die(ExitStatus.MUMBLE, f"Unexpected /login status code {r.status_code}")
    if len(r.cookies) == 0:
        die(ExitStatus.MUMBLE, "No cookies set after login")
    if r.headers.get("Location") != "/":    #где мы?
        die(ExitStatus.MUMBLE, f"Unexpected redirect after login: {r.headers.get('Location')}")

# послали запрос в друзья    
def _add_friend(s, friend_login):
    # _log(f"Add friend: {friend_login}")
    try:
        r = s.post(
            "/send_friend_request",
            data={"friend_login": friend_login},
            allow_redirects=False,
        )
    except Exception as e:
        die(ExitStatus.DOWN, f"Failed to send friend request: {e}")
    
    if r.status_code != 302:
        die(ExitStatus.MUMBLE, f"Unexpected /send_friend_request status code {r.status_code}")

# находим это запрос
def _get_friend_request_id(s, expected_friend_login):
   # _log(f"Get friend request id: {expected_friend_login}")
    try:
        r = s.get("/profile")
    except Exception as e:
        die(ExitStatus.DOWN, f"Failed to access profile: {e}")
    
    if r.status_code != 200:
        die(ExitStatus.MUMBLE, f"Unexpected /profile status code {r.status_code}")
    
    pattern = r'<span>{}</span>[^<]*<div>[^<]*<a href="/accept_friend_request/(\d+)"'.format(re.escape(expected_friend_login))
    match = re.search(pattern, html.unescape(r.text), re.DOTALL)
    if not match:
        die(ExitStatus.MUMBLE, "No friend request found in profile")
    # возвращаем первый айди для нашего друга
    return match.group(1)   

# принимаем запрос на дружбу
def _accept_friend(s, request_id):
    # _log(f"Accept friend: {request_id}")
    try:
        r = s.get(f"/accept_friend_request/{request_id}", allow_redirects=False)
    except Exception as e:
        die(ExitStatus.DOWN, f"Failed to accept friend request: {e}")
    
    if r.status_code != 302:
        die(ExitStatus.MUMBLE, f"Unexpected /accept_friend_request status code {r.status_code}")

# переходим на профиль друга
def _get_profile(s, login):
    _log(f"Get profile for login: {login}")
    try:
        r = s.get(f"/profile/{login}")
    except Exception as e:
        die(ExitStatus.DOWN, f"Failed to access friend profile: {e}")
    
    if r.status_code != 200:
        die(ExitStatus.MUMBLE, f"Unexpected /profile/{login} status code {r.status_code}")
    
    return r.text

# проверяем что на профиле все есть
def _verify_profile(profile_html, name, surname):
    _log(f"Verify profile")
    pattern = r'<h2>\s*({}\s+{})\s*</h2>'.format(re.escape(name), re.escape(surname))
    return bool(re.search(pattern, html.unescape(profile_html)))

# послать открытку
def _send_postcard(s, receiver, message, private):
    # _log(f"Send postcard: receiver: {receiver}, messge: {message}, privateness: {private}")
    try: 
        data = {
            "background": "b.png",  # Предполагаемый фон или i,b
            "front_text": "Test postcard",
            "message": message,
            "receiver": receiver,
            #"font_size":"24",
            "pos_x": "200",
            "pos_y": "200",
            "color": "#000000",
            "font": "Arial",
            "is_private":"off"
        }
        if private:
            data["is_private"] = "on"
        r = s.post("/send_postcard", data=data, allow_redirects=True)
    except Exception as e:
        die(ExitStatus.DOWN, f"Failed to send postcard: {e}")
    
    if r.status_code != 200:
        die(ExitStatus.MUMBLE, f"Unexpected /send_postcard status code {r.status_code}")
    # если allow_redirects=False, те нет тела
    # location = r.headers.get("Location")
    # match = re.search(r'/view_card/(\d+)', location)

    match = re.search(r'/download_card/(\d+)', r.text)
    if not match:
        die(ExitStatus.MUMBLE, "Failed to extract postcard ID")
    
    return int(match.group(1))

# переход на страницу картинки перед скачиванием, хз возможно не нужно
def _view_postcard(session, card_id):
    _log(f"View posctard: card_id: {card_id}")
    try:
        r = session.get(f"/view_card/{card_id}")
    except requests.RequestException as e:
        die(ExitStatus.DOWN, f"Failed to view postcard {card_id}: {e}")
    if r.status_code != 200:
        die(ExitStatus.MUMBLE, f"Unexpected /view_card/{card_id} status code {r.status_code}")
    # Проверяем наличие ссылки на скачивание
    if f"/download_card/{card_id}" not in r.text:
        die(ExitStatus.MUMBLE, f"Download link not found in /view_card/{card_id}")
    return r.text
    
# скачивание открытки
def _download_postcard(s, card_id):
    _log(f"Dowload postcard: {card_id}")
    try:
        r = s.get(f"/download_card/{card_id}")
    except Exception as e:
        die(ExitStatus.DOWN, f"Failed to download postcard: {e}")
    
    if r.status_code != 200:
        die(ExitStatus.MUMBLE, f"Unexpected /download_card/{card_id} status code {r.status_code}")
    if not r.content:
        die(ExitStatus.MUMBLE, f"Empty data downloaded for card {card_id}")
        
    return r.content # тип картинка в байтах

def _set_sign(s, sign):
    # _log(f"Set signature: {sign}")
    try:
        data = {"signature": sign}
        r = s.post("/update_signature", data=data, allow_redirects=True)
    except Exception as e:
        die(ExitStatus.DOWN, f"Failed to update signature: {e}")
    
    if r.status_code != 200:
        die(ExitStatus.MUMBLE, f"Unexpected update singature status code {r.status_code}")

def _ImgDecrypt(image, _len=40):
    _log(f"Image decrypt start")
    img = Image.open(BytesIO(image))

    try:
        width = img.size[0]              
        height = img.size[1]             
        _h = int(height / 2)            
        _w = int(width / 2)             
        pix = img.load()                 

        count = 0
        lenBits = _len * 8
        decryptBinMsg = ""
        
        while _h < height:
            for i in range(_w, width):
                b = pix[i, _h][1]

                if count < lenBits:
                    if (b % 2) == 1:
                        decryptBinMsg = decryptBinMsg + "1"
                        if count == 0:
                            decryptBinMsg = decryptBinMsg + "b"
                        count = count + 1
                    else:
                        decryptBinMsg = decryptBinMsg + "0"
                        if count == 0:
                            decryptBinMsg = decryptBinMsg + "b"
                        count = count + 1
                else:
                    break

            if count < lenBits:
                _h = _h + 1
                _w = 0
            else:
                break

        m = int(decryptBinMsg, 2)
        decryptMsg = m.to_bytes((m.bit_length() + 7) // 8, "big").decode(errors='replace')
        # print(f"Decrypted message: {decryptMsg}", flush=True)
        return decryptMsg
        
    except Exception as e:
        print(f"Error processing image: {str(e)}")
    finally:
        img.close()

def Register(host):
    _log("Checking registration")
    s1 = FakeSession(host, PORT)
    username1, password1, name1, surname1 = _gen_user()
    _register(s1, username1, password1, name1, surname1)
    r = s1.get("/login")
    
    if r.status_code != 200:        # а это доступно?
        die(ExitStatus.MUMBLE, f"Failed to access login page after registration, status code {r.status_code}")

def Login(host):
    _log("Checking login")
    s1 = FakeSession(host, PORT)
    username1, password1, name1, surname1 = _gen_user()
    _register(s1, username1, password1, name1, surname1)
    _login(s1, username1, password1)
    r = s1.get("/profile")
    
    if r.status_code != 200:        # а это доступно?
        die(ExitStatus.MUMBLE, f"Failed to access main page after login, status code {r.status_code}")     
        
def Friend_add_Profile_page(host):
    _log("Checking friend add and profile page")
    s1 = FakeSession(host, PORT)
    s2 = FakeSession(host, PORT)
    
    username1, password1, name1, surname1 = _gen_user()
    username2, password2, name2, surname2 = _gen_user()
    
    _register(s1, username1, password1, name1, surname1)
    _register(s2, username2, password2, name2, surname2)
    
    _login(s1, username1, password1)
    _login(s2, username2, password2)
    # дружим
    _add_friend(s1, username2)
    request_id = _get_friend_request_id(s2, username1)
    _accept_friend(s2, request_id)
    # подглядываем
    profile = _get_profile(s1, username2)
    if not _verify_profile(profile, name2, surname2):
        die(ExitStatus.MUMBLE, f"Friend profile does not contain expected name and surname")

def Download_postcard_check(host):
    _log("Checking postcard sending and downloading")
    s1 = FakeSession(host, PORT)
    s2 = FakeSession(host, PORT)
    s3 = FakeSession(host, PORT)
    
    username1, password1, name1, surname1 = _gen_user()
    username2, password2, name2, surname2 = _gen_user()
    username3, password3, name3, surname3 = _gen_user()
    
    _register(s1, username1, password1, name1, surname1)
    _register(s2, username2, password2, name2, surname2)
    _register(s3, username3, password3, name3, surname3)
    
    _login(s1, username1, password1)
    _login(s2, username2, password2)
    _login(s3, username3, password3)
    # дружим
    _add_friend(s1, username2)
    request_id = _get_friend_request_id(s2, username1)
    _accept_friend(s2, request_id)
    # отправка писем
    open_postcard_id = _send_postcard(s1, username2, message="Test open postcard", private=False)
    private_postcard_id = _send_postcard(s1, username2, message="Test private postcard", private=True)
    # # Перейти на открытки по ID           если можно скачивать сразу, то не нужно
    # _view_postcard(s3, open_postcard_id)
    # _view_postcard(s3, private_postcard_id)
    # скачиваем
    open_data = _download_postcard(s3, open_postcard_id)
    private_data = _download_postcard(s3, private_postcard_id)
    # это норм, не норм? вроде как должно фикситься 
    if not open_data or not private_data:
        die(ExitStatus.MUMBLE, f"Failed to download postcards")

# бинарь-уведомления
def Postcard_message_check(host: str):
    _log(f"Postcard message check")
    try:
        s1 = FakeSession(host, PORT)
        s2 = FakeSession(host, PORT)

        username1, password1, name1, surname1 = _gen_user()
        username2, password2, name2, surname2 = _gen_user()

        _log("Registering two users")
        _register(s1, username1, password1, name1, surname1)
        _register(s2, username2, password2, name2, surname2)

        _log("Logging in both users")
        _login(s1, username1, password1)
        _login(s2, username2, password2)

        _log("Sending and accepting friend request")
        _add_friend(s1, username2)
        request_id = _get_friend_request_id(s2, username1)
        _accept_friend(s2, request_id)

        _log("Fetching notification token")
        profile_html = s1.get("/profile").text
        token_match = re.search(r'<p><strong>Токен:</strong>\s*([a-f0-9]+)</p>', profile_html)
        if not token_match:
            _log("Notification token not found")
            die(ExitStatus.MUMBLE, "Notification token not found")
        token = token_match.group(1)

        test_message = "SECRET_TEST_" + rand_string(16)
        _log(f"Sending test postcard with message: {test_message}")
        _send_postcard(s2, username1, test_message, private=True)

        # Подключаемся к бинарному сервису через сокет
        _log(f"Connecting to mail_panda binary on {host}:31337")
        p = remote(host, 31337)

        p.recvuntil("Введите токен (HEX):".encode('utf-8'))  # строка -> байты
        p.sendline(token.encode() if isinstance(token, str) else token)

        p.recvuntil(b'2.Exit')  # байтовая строка
        p.sendline(b'1')
        
        # Формируем ожидаемую строку
        expected_line = f"Новая открытка от {username2}, сообщение: {test_message}"

        _log("Waiting for expected notification...")

        start_time = time.time()
        found = False

        while time.time() - start_time < 10:
            try:
                line = p.recvline()
                if not line:
                    continue
                decoded_line = line.decode('utf-8', errors='ignore').strip()
                _log(f"Received line: {decoded_line}")
                if expected_line in decoded_line:
                    found = True
                    break
            except EOFError:
                # Сервер закрыл соединение — выход
                break

        p.close()

        if found == False:
            _log("Test message not found in output after 10 seconds")
            die(ExitStatus.CORRUPT, "Test message not found in notifications")
        else:
            _log("Test message found! Everything is OK!")

    except requests.exceptions.RequestException as e:
        _log(f"Network error: {e}")
        die(ExitStatus.DOWN, f"Network error: {str(e)}")
    except Exception as e:
        _log(f"Unexpected error: {e}")
        die(ExitStatus.MUMBLE, f"Unexpected error: {str(e)}")

#список пользователей
def List_of_users_check(host):
    _log("List of users check")
    s1 = FakeSession(host, PORT)
    username1, password1, name1, surname1 = _gen_user()
    _register(s1, username1, password1, name1, surname1)
    _login(s1, username1, password1)
    r = s1.get("/users")
    
    if r.status_code != 200:        # а это доступно?
        die(ExitStatus.MUMBLE, f"Failed to access users page after login, status code {r.status_code}")
    # начинаем искать пользователей
    soup = BeautifulSoup(r.text, 'html.parser')

    # Попробуем найти логины в <span class="hidden" data-users="...">
    hidden_span = soup.find("span", {"class": "hidden", "data-users": True})
    if hidden_span:
        try:
            b64_data = hidden_span["data-users"]
            decoded = base64.b64decode(b64_data).decode()
            logins = [login.strip() for login in decoded.split(",") if login.strip()]
        except Exception as e:
            _log(f"[!] Не удалось распарсить логины из data-users: {e}")

    if not username1 in logins: # Ищем пользователя среди логинов
        die(ExitStatus.MUMBLE, f"Username not found in logins {r.status_code}") 

def Signature(host):
    _log("Checking signature")
    s1 = FakeSession(host, PORT)
    s2 = FakeSession(host, PORT)
    
    username1, password1, name1, surname1 = _gen_user()
    username2, password2, name2, surname2 = _gen_user()

    _register(s1, username1, password1, name1, surname1)
    _register(s2, username2, password2, name2, surname2)

    _login(s1, username1, password1)
    _login(s2, username2, password2)
    
    _add_friend(s1, username2)
    request_id = _get_friend_request_id(s2, username1)
    _accept_friend(s2, request_id)

    fake = Faker()
    sign1 = fake.pystr(max_chars=15)
    sign2 = fake.pystr(max_chars=15)

    _set_sign(s1, sign1)
    card1_id = _send_postcard(s1, username2, message="aboba", private=False)
    card1 = _download_postcard(s1, card1_id)

    _set_sign(s1, sign2)
    card2_id = _send_postcard(s1, username2, message="aboba", private=False)
    card2 = _download_postcard(s1, card2_id)

    _set_sign(s1, sign1)
    card3_id = _send_postcard(s1, username2, message="aboba", private=False)
    card3 = _download_postcard(s1, card3_id)

    get_sign1 = _ImgDecrypt(card1, _len=15)
    get_sign2 = _ImgDecrypt(card2, _len=15)
    get_sign3 = _ImgDecrypt(card3, _len=15)

    if not (get_sign1 == get_sign3 and get_sign1 != get_sign2):
        die(ExitStatus.MUMBLE, f"Signatures not match")

# Основные функции        
def check(host: str):
    # Проверка всего функционал сервиса, но главное проверить всё, что мы не хотим, чтобы удалили с сервиса.
    # Также для проверки можем посылать забитые тестовыми данными сообщения. Например для проверки сервиса бинарного проверять авторов.
    
    #Register check
    Register(host)
    
    #Login check
    Login(host)
    
    #List of users check
    List_of_users_check(host)
    
    #Friend add + Profile page check
    Friend_add_Profile_page(host)
        
    #Download postcard check
    Download_postcard_check(host)
        
    #Surname vuln

    #Signature vuln
    Signature(host)

    #Postcard message vuln
    Postcard_message_check(host)
    
    die(ExitStatus.OK, "Check ALL OK")


def put(host: str, flag_id: str, flag: str, vuln: int):
    postcard_id1 = None

    if vuln == 1:
        #vuln - surname кладем в фамилию при регистрации
        try:
            # _log("[Checker PUT] Surname vuln")
            # регистрация пользователя
            s1 = FakeSession(host, PORT)
            username1, password1, name1, surname1 = _gen_user()
            # ввод флага в поле фамилии
            _register(s1, username1, password1, name1, flag)
        except Exception as e:
            _log(f"Failed to put flag in surname (vuln=1): {e}")
            die(ExitStatus.MUMBLE, f"Failed to put flag: {e}")
    elif vuln == 2:
        # vuln - signature стеганография на открытках, прописываем из профиля в поле
        try:
            # _log("[Checker PUT] Signature vuln")
            # регистрация пользователя
            s1 = FakeSession(host, PORT)
            username1, password1, name1, surname1 = _gen_user()
            _register(s1, username1, password1, name1, surname1)
            # вход в аккаунт
            _login(s1, username1, password1)
            # обноление подписи
            _set_sign(s1, flag)
            
        except Exception as e:
            _log(f"Failed to put flag in signature (vuln=2): {e}")
            die(ExitStatus.MUMBLE, f"Failed to put flag: {e}")
    elif vuln == 3:
        # vuln - postcard text приватное сообщение открытки, прописываем при отправлении открытки
        try:
            # _log("[Checker PUT] Postcard message vuln")
            # создаем 2 пользователя
            s1 = FakeSession(host, PORT)
            s2 = FakeSession(host, PORT)
            username1, password1, name1, surname1 = _gen_user()
            username2, password2, name2, surname2 = _gen_user()
            _register(s1, username1, password1, name1, surname1)
            _register(s2, username2, password2, name2, surname2)
            _login(s1, username1, password1)
            _login(s2, username2, password2)
            # отправка приглашения в друзья 2-ому пользователю
            _add_friend(s1, username2)
            request_id = _get_friend_request_id(s2, username1)
            # на 2-ом пользователе принимаем запрос в друзья
            _accept_friend(s2, request_id)
            # возвращаемся на 1-ого пользователя
            # и пишем открытку в закрытом виде, в поле текста вставляем флаг
            postcard_id1 = _send_postcard(s1, username2, flag, private=True)
        except Exception as e:
            _log(f"Failed to put flag in send message (vuln=3): {e}")
            die(ExitStatus.MUMBLE, f"Failed to put flag: {e}")
    else:
        die(ExitStatus.CHECKER_ERROR, f"vuln id out of range: {vuln}")

    jd = json.dumps(
        {
            "username": username1,
            "password": password1,
            "postcard_id": postcard_id1,
        }
    )

    print(jd, flush=True)  # It's our flag_id now! Tell it to jury!
    die(ExitStatus.OK, f"{jd}")


def get(host: str, flag_id: str, flag: str, vuln: int):
    try:
        _log(f"flag_id in get: {flag_id}")
        data = json.loads(flag_id)
        _log(f"data in get: {data}")
        if not data:
            raise ValueError
    except:
        die(ExitStatus.CHECKER_ERROR, f"Unexpected flagID from jury: {flag_id}!")

    if vuln == 1:
        #vuln - surname кладем в фамилию при регистрации
        _log("[Checker GET] Surname vuln 1")
        try:
            s1 = FakeSession(host, PORT)
            # вход в аккаунт
            _login(s1, data["username"], data["password"])
            # вход в профиль
            profile_html = s1.get("/profile").text
            # вытаскиваем из поля surname флаг
            soup = BeautifulSoup(profile_html, 'html.parser')
            page_text = soup.get_text()
            # _log(f"page_text: {page_text}")
            # _log(f"flag: {flag}")
            
            if flag not in page_text:
                _log("The flags are not same in surname (vuln=1)")
                die(ExitStatus.CORRUPT, f"Failed to get flag")
        except Exception as e:
            _log(f"Failed to get flag from surname (vuln=1): {e}")
            die(ExitStatus.CORRUPT, f"Failed to get flag: {e}")
        
    elif vuln == 2:
        # vuln - signature стеганография на открытках, прописываем из профил¤ в поле
        _log("[Checker GET] Signature vuln 2")
        try:
            s1 = FakeSession(host, PORT)
            # вход в аккаунт
            _login(s1, data["username"], data["password"])
            # вход в профиль
            profile_html = s1.get("/profile").text
            # вытаскиваем из поля signature флаг
            soup = BeautifulSoup(profile_html, 'html.parser')
            # Ищем <input name="signature">
            signature_input = soup.find('input', {'name': 'signature'})
            if not signature_input:
                _log("No input element with name='signature' found")
                die(ExitStatus.CORRUPT, "No signature input found in profile")

            outputflag = signature_input.get('value')
            # _log(f"outputflag: {outputflag}")
            # _log(f"flag: {flag}")

            if outputflag != flag:
                _log("The flags are not same in signature (vuln=2)")
                die(ExitStatus.CORRUPT, f"Failed to get flag")
        except Exception as e:
            _log(f"Failed to get flag from signature (vuln=2): {e}")
            die(ExitStatus.CORRUPT, f"Failed to get flag: {e}")
    elif vuln == 3:
        # vuln - postcard text приватное сообщение открытки, прописываем при отправлении открытки
        _log("[Checker GET] Postcard message vuln 3")
        try:
            s1 = FakeSession(host, PORT)
            # вход в аккаунт
            _login(s1, data["username"], data["password"])
            # вход в профиль
            profile_html = s1.get("/profile").text
            # выбор нужной отправленной открытки в списке своих отправленных
            postcardID = data["postcard_id"]
            # переход на страницу открытки
            postcard_html = _view_postcard(s1, postcardID)
            # вытаскиваем флаг из поля текста открытки
            soup = BeautifulSoup(postcard_html, 'html.parser')
            outputflag = soup.find(string=flag)
            if outputflag != flag:
                _log("The flags are not same in postcard message (vuln=3)")
                die(ExitStatus.CORRUPT, f"Failed to get flag")
        except Exception as e:
            _log(f"Failed to get flag from postcard message (vuln=3): {e}")
            die(ExitStatus.CORRUPT, f"Failed to get flag: {e}")
                    
    die(ExitStatus.OK, f"All OK! Successfully retrieved a flag from api")


def rand_string(
    n=12, alphabet=string.ascii_uppercase + string.ascii_lowercase + string.digits
):
    return "".join(random.choice(alphabet) for _ in range(n))


def _log(obj):
    if DEBUG and obj:
        caller = inspect.stack()[1].function
        print(f"[{caller}] {obj}", file=sys.stderr)
    return obj


class ExitStatus(Enum):
    OK = 101
    CORRUPT = 102
    MUMBLE = 103
    DOWN = 104
    CHECKER_ERROR = 110


def die(code: ExitStatus, msg: str):
    if msg:
        print(msg, file=sys.stderr)
    exit(code.value)


def info():
    print("vulns: 1:2:2", flush=True)#surname, signature, postcard text
    #print("timeout: 60", flush=True)# ломает чекер на пут гет
    exit(101)


def _main():
    # _log(f"Received arguments: {argv}, length: {len(argv)}\n")
    try:
        cmd = argv[1]
        hostname = argv[2]
        if cmd == "put":
            if len(argv) != 6:
                raise IndexError(f"Expected 6 arguments for put, got {len(argv)}")
            fid, flag, vuln = argv[3], argv[4], int(argv[5])
            # _log(f"Calling put with: hostname={hostname}, fid={fid}, flag={flag}, vuln={vuln}")
            put(hostname, fid, flag, vuln)
        elif cmd == "get":
            if len(argv) != 6:
                raise IndexError(f"Expected 6 arguments for get, got {len(argv)}")
            fid, flag, vuln = argv[3], argv[4], int(argv[5])
            _log(f"Calling get with: hostname={hostname}, fid={fid}, flag={flag}, vuln={vuln}")
            get(hostname, fid, flag, vuln)
        elif cmd == "check":
            check(hostname)
        elif cmd == "info":
            info()
        else:
            raise ValueError(f"Unknown command: {cmd}")
    except IndexError as e:
        _log(f"IndexError: {e}")
        die(
            ExitStatus.CHECKER_ERROR,
            f"Usage: {argv[0]} check|put|get IP FLAGID FLAG VULN",
        )
    except ValueError as e:
        _log(f"ValueError: {e}")
        die(
            ExitStatus.CHECKER_ERROR,
            f"Usage: {argv[0]} check|put|get IP FLAGID FLAG VULN",
        )
    except Exception as e:
        _log(f"Unexpected error: {e}")
        die(
            ExitStatus.CHECKER_ERROR,
            f"Checker error: {e}",
        )


if __name__ == "__main__":
    _main()