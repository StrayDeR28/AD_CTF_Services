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

# Make all random more random.
import requests
from faker import Faker

random = random.SystemRandom()

""" <config> """
# SERVICE INFO
PORT = 8888
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
    faker = Faker()
    name = faker.first_name()
    surname = faker.last_name()
    username = faker.user_name()
    password = faker.password(length=12)
    
    return username, password, name, surname

# регистрация
def _register(s, username, password, name, surname):
    try:
        r = s.post(
            "/register",
            data={"login": username, "password": password, "name": name, "surname": surname},
            allow_redirects=False,
        )
    except Exception as e:
        die(ExitStatus.DOWN, f"Failed to register: {e}")
    
    if r.status_code != 302:
        die(ExitStatus.MUMBLE, f"Unexpected /register status code {r.status_code}")
    if len(r.cookies) == 0:
        die(ExitStatus.MUMBLE, "No cookies set after registration")
    if r.headers.get("Location") != "/login":   #где мы?
        die(ExitStatus.MUMBLE, f"Unexpected redirect after registration: {r.headers.get('Location')}")

# логирование
def _login(s, username, password):
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
    try:
        r = s.get(f"/accept_friend_request/{request_id}", allow_redirects=False)
    except Exception as e:
        die(ExitStatus.DOWN, f"Failed to accept friend request: {e}")
    
    if r.status_code != 302:
        die(ExitStatus.MUMBLE, f"Unexpected /accept_friend_request status code {r.status_code}")

# переходим на профиль друга
def _get_profile(s, login):
    try:
        r = s.get(f"/profile/{login}")
    except Exception as e:
        die(ExitStatus.DOWN, f"Failed to access friend profile: {e}")
    
    if r.status_code != 200:
        die(ExitStatus.MUMBLE, f"Unexpected /profile/{login} status code {r.status_code}")
    
    return r.text

# проверяем что на профиле все есть
def _verify_profile(profile_html, name, surname):
    pattern = r'<h2>\s*({}\s+{})\s*</h2>'.format(re.escape(name), re.escape(surname))
    return bool(re.search(pattern, html.unescape(profile_html)))

# послать открытку
def _send_postcard(s, receiver, message, private):
    try: # уточнить за параметры картинки++++++++++++++++++++++++
        data = {
            "background": "default.png",  # Предполагаемый фон или i,b ?
            "front_text": "Test postcard",
            "message": message,
            "receiver": receiver,
            "pos_x": "50",
            "pos_y": "50",
            "color": "#000000",
            "font": "Arial",
        }
        if private:
            data["is_private"] = "on"
        r = s.post("/send_postcard", data=data, allow_redirects=True)
    except Exception as e:
        die(ExitStatus.DOWN, f"Failed to send postcard: {e}")
    
    if r.status_code != 200:
        die(ExitStatus.MUMBLE, f"Unexpected /send_postcard status code {r.status_code}")
    # тут надо найти айди, как конкретно пока хз+++++++++++++++++++++
    match = re.search(r'/view_card/(\d+)', r.text)
    if not match:
        die(ExitStatus.MUMBLE, "Failed to extract postcard ID")
    
    return int(match.group(1))

# скачивание открытки
def _download_postcard(s, card_id):
    try:
        r = s.get(f"/download_card/{card_id}")
    except Exception as e:
        die(ExitStatus.DOWN, f"Failed to download postcard: {e}")
    
    if r.status_code != 200:
        die(ExitStatus.MUMBLE, f"Unexpected /download_card/{card_id} status code {r.status_code}")
    
    return r.content # тип картинка в байтах
    
# Основные функции        
def check(host: str):
    # Проверка всего функционал сервиса, но главное проверить всё, что мы не хотим, чтобы удалили с сервиса.
    # Также для проверки можем посылать забитые тестовыми данными сообщения. Например для проверки сервиса бинарного проверять авторов.
    flag_check = True
    
    #Register check
    _log("Checking registration")
    s1 = FakeSession(host, PORT)
    username1, password1, name1, surname1 = _gen_user()
    _register(s1, username1, password1, name1, surname1)
    r = s1.get("/login")
    
    if r.status_code != 200:        # а это доступно?
        die(ExitStatus.MUMBLE, f"Failed to access login page after registration, status code {r.status_code}")
        flag_check = False
    
    #Login check
    _log("Checking login")
    _login(s1, username1, password1)
    r = s1.get("/")
    
    if r.status_code != 200:        # а это доступно?
        die(ExitStatus.MUMBLE, f"Failed to access main page after login, status code {r.status_code}")
        flag_check = False
        
    #Friend add + Profile page check
    _log("Checking friend add and profile page")
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
    profile = _get_profile(s1, username2)
    
    if not _verify_profile(profile, name2, surname2):
        die(ExitStatus.MUMBLE, f"Friend profile does not contain expected name and surname")
        flag_check = False
        
    #Download postcard check
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
    
    _add_friend(s1, username2)
    request_id = _get_friend_request_id(s2, username1)
    _accept_friend(s2, request_id)
    open_postcard_id = _send_postcard(s1, username2, message="Test open postcard", private=False)
    private_postcard_id = _send_postcard(s1, username2, message="Test private postcard", private=True)
    open_data = _download_postcard(s3, open_postcard_id)
    private_data = _download_postcard(s3, private_postcard_id)
    # это норм, не норм? вроде как должно фикситься 
    if not open_data or not private_data:
        die(ExitStatus.MUMBLE, f"Failed to download postcards")
        flag_check = False
        
    #Surname vuln

    #Signature vuln

    #Postcard message vuln

    if flag_check:
        die(ExitStatus.OK, "Check ALL OK")


def put(host: str, flag_id: str, flag: str, vuln: int):
    if vuln == 1:
        #vuln - surname кладем в фамилию при регистрации

        pass
    elif vuln == 2:
        # vuln - signature стеганография на открытках, прописываем из профиля в поле

        pass
    elif vuln == 3:
        # vuln - postcard text приватное сообщение открытки, прописываем при отправлении открытки

        pass
    else:
        die(ExitStatus.CHECKER_ERROR, f"vuln id out of range: {vuln}")

    die(ExitStatus.OK, "")

def get(host: str, flag_id: str, flag: str, vuln: int):
    if vuln == 1:
        #vuln - surname кладем в фамилию при регистрации
        
        pass
    elif vuln == 2:
        # vuln - signature стеганография на открытках, прописываем из профиля в поле

        pass
    elif vuln == 3:
        # vuln - postcard text приватное сообщение открытки, прописываем при отправлении открытки
        
        pass
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
    print("vulns: 1:2:2", flush=True, end="")#surname, signature, postcard text
    exit(101)


def _main():
    try:
        cmd = argv[1]
        hostname = argv[2]
        if cmd == "get":
            fid, flag, vuln = argv[3], argv[4], int(argv[5])
            get(hostname, fid, flag, vuln)
        elif cmd == "put":
            fid, flag, vuln = argv[3], argv[4], int(argv[5])
            put(hostname, fid, flag, vuln)
        elif cmd == "check":
            check(hostname)
        elif cmd == "info":
            info()
        else:
            raise IndexError
    except IndexError:
        die(
            ExitStatus.CHECKER_ERROR,
            f"Usage: {argv[0]} check|put|get IP FLAGID FLAG VULN",
        )


if __name__ == "__main__":
    _main()