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

random = random.SystemRandom()

""" <config> """
# SERVICE INFO
PORT = 8888
EXPLOIT_NAME = argv[0]

# DEBUG -- logs to stderr, TRACE -- log HTTP requests
DEBUG = os.getenv("DEBUG", True)
TRACE = os.getenv("TRACE", False)
""" </config> """

def check(host: str):
    # Проверка всего функционал сервиса, но главное проверить всё, что мы не хотим, чтобы не удалили с сервиса.
    # Также для проверки можем посылать забитые тестовыми данными сообщения. Например для проверки сервиса бинарного проверять авторов.
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