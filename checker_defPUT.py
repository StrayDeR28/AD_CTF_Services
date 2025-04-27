def put(host: str, flag_id: str, flag: str, vuln: int):
    
    if vuln == 1:
        #vuln - surname кладем в фамилию при регистрации
        
        try:
            #_log("[Checker PUT] Surname vuln")
            # регистрация пользователя
            s1 = FakeSession(host, PORT)
            username1, password1, name1, surname1 = _gen_user()
            # ввод флага в поле фамилии
            _register(s1, username1, password1, name1, flag)
        except Exception as e:
            log.failure(f"Failed to put flag in surname (vuln=1): {e}")
            die(ExitStatus.MUMBLE, f"Failed to put flag: {e}")

        pass
    elif vuln == 2:
        # vuln - signature стеганография на открытках, прописываем из профиля в поле
        
        try:
            #_log("[Checker PUT] Signature vuln")
            # регистрация пользователя
            s1 = FakeSession(host, PORT)
            username1, password1, name1, surname1 = _gen_user()
            _register(s1, username1, password1, name1, surname1)
            # вход в аккаунт
            _login(s1, username1, password1)
            # вход в профиль
            #profile = _get_profile(s1, username1)
            profile_html = s1.get("/profile").text
            # вставляем в поле signature флаг
            re.sub(r'<input type="text" name="signature" value="\s*([A-Za-z0-9_]+)" required>', flag, profile_html)
        except Exception as e:
            log.failure(f"Failed to put flag in signature (vuln=2): {e}")
            die(ExitStatus.MUMBLE, f"Failed to put flag: {e}")
        

        pass
    elif vuln == 3:
        # vuln - postcard text приватное сообщение открытки, прописываем при отправлении открытки
        
        try:
            #_log("[Checker PUT] Postcard message vuln")
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
            _send_postcard(s1, username2, flag, private=True)
        except Exception as e:
            log.failure(f"Failed to put flag in send message (vuln=3): {e}")
            die(ExitStatus.MUMBLE, f"Failed to put flag: {e}")
        

        pass
    else:
        die(ExitStatus.CHECKER_ERROR, f"vuln id out of range: {vuln}")

    jd = json.dumps(
        {
            "username": username1,
            "password": password1,
        }
    )

    print(jd, flush=True)  # It's our flag_id now! Tell it to jury!
    die(ExitStatus.OK, "")
