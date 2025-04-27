def get(host: str, flag_id: str, flag: str, vuln: int):
    try:
        data = json.loads(flag_id)
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
            outputflag = soup.find(string=flag)
            if outputflag != flag:
                log.failure("The flags are not same in surname (vuln=1)")
                die(ExitStatus.CORRUPT, f"Failed to get flag")
        except Exception as e:
            log.failure(f"Failed to get flag from surname (vuln=1): {e}")
            die(ExitStatus.CORRUPT, f"Failed to get flag: {e}")
        
        pass
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
            outputflag = soup.find(string=flag)
            if outputflag != flag:
                log.failure("The flags are not same in signature (vuln=2)")
                die(ExitStatus.CORRUPT, f"Failed to get flag")
        except Exception as e:
            log.failure(f"Failed to get flag from signature (vuln=2): {e}")
            die(ExitStatus.CORRUPT, f"Failed to get flag: {e}")

        pass
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
            _view_postcard(s1, host, postcardID)
            # вытаскиваем флаг из поля текста открытки
            soup = BeautifulSoup(profile_html, 'html.parser')
            outputflag = soup.find(string=flag)
            if outputflag != flag:
                log.failure("The flags are not same in postcard message (vuln=3)")
                die(ExitStatus.CORRUPT, f"Failed to get flag")
        except Exception as e:
            log.failure(f"Failed to get flag from postcard message (vuln=3): {e}")
            die(ExitStatus.CORRUPT, f"Failed to get flag: {e}")
        
        pass
    die(ExitStatus.OK, f"All OK! Successfully retrieved a flag from api")
