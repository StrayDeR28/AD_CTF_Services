import os
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    send_from_directory,
)
from flask_login import (
    LoginManager,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Friend, Postcard
from PIL import Image, ImageDraw, ImageFont
import random
import base64
from Crypto.Cipher import ChaCha20
from confluent_kafka import Producer
from confluent_kafka.admin import AdminClient, NewTopic
from datetime import datetime
from encr import ImgEncrypt

BROKER = "localhost:9092"
POSTCARDS_FOLDER = "static/postcards"  # Относительно корня проекта

app = Flask(__name__)
app.config["POSTCARDS_FOLDER"] = POSTCARDS_FOLDER
app.config["SECRET_KEY"] = "your-secret-key-here"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///postcards.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = "static/images/backgrounds"
app.config["ALLOWED_EXTENSIONS"] = {"png", "jpg", "jpeg"}

# Инициализация расширений
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Создаем папку для загрузок, если ее нет
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


# Загрузка пользователя
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
@login_required
def main():
    backgrounds = os.listdir(app.config["UPLOAD_FOLDER"])

    # Получаем друзей для выпадающего списка
    friends = Friend.query.filter(
        (
            (Friend.friend1_login == current_user.login)
            | (Friend.friend2_login == current_user.login)
        ),
        Friend.is_approved == True,
    ).all()

    friend_logins = []
    for f in friends:
        if f.friend1_login == current_user.login:
            friend_logins.append(f.friend2_login)
        else:
            friend_logins.append(f.friend1_login)

    friends = User.query.filter(User.login.in_(friend_logins)).all()

    # Получаем последние 5 не приватных открыток от всех пользователей
    recent_postcards = (
        Postcard.query.filter(Postcard.is_private == False)
        .order_by(Postcard.created_at.desc())
        .limit(5)
        .all()
    )

    return render_template(
        "main.html",
        backgrounds=backgrounds,
        friends=friends,
        recent_postcards=recent_postcards,
    )


# Страница входа
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main"))

    if request.method == "POST":
        login = request.form.get("login")
        password = request.form.get("password")
        remember = True if request.form.get("remember") else False

        user = User.query.filter_by(login=login).first()

        if not user or not check_password_hash(user.password, password):
            flash("Неверный логин или пароль")
            return redirect(url_for("login"))

        login_user(user, remember=remember)
        return redirect(url_for("main"))

    return render_template("login.html")


# Страница регистрации
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main"))

    if request.method == "POST":
        login = request.form.get("login")
        password = request.form.get("password")
        name = request.form.get("name")
        surname = request.form.get("surname")

        # Проверяем, существует ли пользователь
        user = User.query.filter_by(login=login).first()

        if user:
            flash("Пользователь с таким логином уже существует")
            return redirect(url_for("register"))

        # Генерируем подпись для открыток
        signature = generate_signature()

        # Генерируем токен
        token = generate_token(login)

        create_topic(login)

        # Создаем нового пользователя
        new_user = User(
            login=login,
            password=generate_password_hash(password, method="pbkdf2:sha256"),
            name=name,
            surname=surname,
            postcard_signature=signature,
            notification_token=token,
        )

        db.session.add(new_user)
        db.session.commit()

        flash("Регистрация прошла успешно. Теперь вы можете войти.")
        return redirect(url_for("login"))

    return render_template("register.html")


# Выход
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# Профиль пользователя
@app.route("/profile")
@login_required
def profile():
    # Получаем входящие запросы в друзья
    incoming_requests = Friend.query.filter(
        Friend.friend2_login == current_user.login, Friend.is_approved == False
    ).all()

    # Получаем список друзей
    friends = get_friends(current_user.login)

    # Получаем отправленные и полученные открытки
    sent_postcards = Postcard.query.filter_by(sender_login=current_user.login).all()
    received_postcards = Postcard.query.filter_by(
        receiver_login=current_user.login
    ).all()

    return render_template(
        "profile.html",
        incoming_requests=incoming_requests,
        friends=friends,
        sent_postcards=sent_postcards,
        received_postcards=received_postcards,
    )


@app.route("/profile/<login>")
@login_required
def friend_profile(login):
    if login == current_user.login:
        return redirect(url_for("profile"))

    is_friend = Friend.query.filter(
        ((Friend.friend1_login == current_user.login) & (Friend.friend2_login == login))
        | (
            (Friend.friend1_login == login)
            & (Friend.friend2_login == current_user.login)
        ),
    ).first()

    user = User.query.filter_by(login=login).first_or_404()

    if is_friend:
        return render_template("friend_profile.html", user=user, is_friend=True)
    else:
        limited_info = {
            "login": user.login,
            "initials": f"{user.name[0] if user.name else ''}{user.surname[0] if user.surname else ''}",
            "signature": generate_famous_signature(),  # Используем случайную подпись
        }
        return render_template(
            "friend_profile.html", user=limited_info, is_friend=False
        )


# Обновление подписи
@app.route("/update_signature", methods=["POST"])
@login_required
def update_signature():
    new_signature = request.form.get("signature")

    if not new_signature:
        flash("Подпись не может быть пустой")
        return redirect(url_for("profile"))

    # Проверяем, что подпись уникальна
    existing = User.query.filter_by(postcard_signature=new_signature).first()
    if existing and existing.id != current_user.id:
        flash("Такая подпись уже используется")
        return redirect(url_for("profile"))

    current_user.postcard_signature = new_signature
    db.session.commit()

    flash("Подпись успешно обновлена")
    return redirect(url_for("profile"))


# Отправка запроса в друзья
@app.route("/send_friend_request", methods=["POST"])
@login_required
def send_friend_request():
    friend_login = request.form.get("friend_login")

    if not friend_login:
        flash("Введите логин друга")
        return redirect(url_for("profile"))

    if friend_login == current_user.login:
        flash("Вы не можете добавить себя в друзья")
        return redirect(url_for("profile"))

    friend = User.query.filter_by(login=friend_login).first()
    if not friend:
        flash("Пользователь не найден")
        return redirect(url_for("profile"))

    # Проверяем, не отправили ли уже запрос
    existing_request = Friend.query.filter(
        (
            (Friend.friend1_login == current_user.login)
            & (Friend.friend2_login == friend_login)
        )
        | (
            (Friend.friend1_login == friend_login)
            & (Friend.friend2_login == current_user.login)
        )
    ).first()

    if existing_request:
        if existing_request.is_approved:
            flash("Этот пользователь уже у вас в друзьях")
        else:
            flash("Запрос уже отправлен")
        return redirect(url_for("profile"))

    # Создаем новый запрос
    new_request = Friend(
        friend1_login=current_user.login, friend2_login=friend_login, is_approved=False
    )

    db.session.add(new_request)
    db.session.commit()

    msg = f"Пришел запрос в друзья от: {current_user.login}"
    send_messages(friend_login, msg)

    flash("Запрос в друзья отправлен")
    return redirect(url_for("profile"))


# Принятие запроса в друзья
@app.route("/accept_friend_request/<int:request_id>")
@login_required
def accept_friend_request(request_id):
    friend_request = Friend.query.get(request_id)

    if not friend_request or friend_request.friend2_login != current_user.login:
        flash("Запрос не найден")
        return redirect(url_for("profile"))

    friend_request.is_approved = True
    db.session.commit()

    flash("Запрос в друзья принят")
    return redirect(url_for("profile"))


# Отклонение запроса в друзья
@app.route("/reject_friend_request/<int:request_id>")
@login_required
def reject_friend_request(request_id):
    friend_request = Friend.query.get(request_id)

    if not friend_request or friend_request.friend2_login != current_user.login:
        flash("Запрос не найден")
        return redirect(url_for("profile"))

    db.session.delete(friend_request)
    db.session.commit()

    flash("Запрос в друзья отклонен")
    return redirect(url_for("profile"))


# Удаление друга
@app.route("/remove_friend/<friend_login>")
@login_required
def remove_friend(friend_login):
    friendship = Friend.query.filter(
        (
            (Friend.friend1_login == current_user.login)
            & (Friend.friend2_login == friend_login)
        )
        | (
            (Friend.friend1_login == friend_login)
            & (Friend.friend2_login == current_user.login)
        )
    ).first()

    if not friendship:
        flash("Друг не найден")
        return redirect(url_for("profile"))

    db.session.delete(friendship)
    db.session.commit()

    flash("Друг удален")
    return redirect(url_for("profile"))


@app.route("/send_postcard", methods=["POST"])
@login_required
def send_postcard():
    try:
        # Получаем данные
        receiver_login = request.form.get("receiver")
        front_text = request.form.get("front_text")
        message = request.form.get("message")
        is_private = request.form.get("is_private") == "on"
        background = request.form.get("background")

        # Валидация
        if not all([receiver_login, front_text, background]):
            flash("Заполните все обязательные поля")
            return redirect(url_for("main"))

        # Проверка друга
        if not is_friend(current_user.login, receiver_login):
            flash("Можно отправлять только друзьям")
            return redirect(url_for("main"))

        # Создаем уникальное имя файла
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        filename = f"postcard_{current_user.login}_{timestamp}.png"
        filepath = os.path.join(POSTCARDS_FOLDER, filename)

        # Создаем и сохраняем изображение
        img = create_card_image(
            front_text,
            background,
            request.form.get("font", "Arial"),
            request.form.get("color", "#000000"),
            int(request.form.get("pos_x", 50)),
            int(request.form.get("pos_y", 50)),
            int(request.form.get("font_size", 24)),
        )

        img = ImgEncrypt(img, current_user.postcard_signature)

        img.save(filepath, "PNG")
        app.logger.info(f"Открытка сохранена в {filepath}")

        # Проверяем что файл создан
        if not os.path.exists(filepath):
            raise Exception("Файл открытки не создан")

        # Создаем запись в БД
        new_postcard = Postcard(
            sender_login=current_user.login,
            receiver_login=receiver_login,
            text=message,
            is_private=is_private,
            image_path=os.path.join("postcards", filename),
            created_at=datetime.now(),
        )

        db.session.add(new_postcard)
        db.session.commit()
        app.logger.info(f"Запись создана с ID {new_postcard.id}")

        # Отправка уведомления
        send_messages(receiver_login, f"Новая открытка от {current_user.login}")

        flash("Открытка успешно отправлена!")
        return redirect(url_for("main"))

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Ошибка: {str(e)}", exc_info=True)
        flash(f"Ошибка: {str(e)}")
        return redirect(url_for("main"))


# Просмотр открытки
@app.route("/view_card/<int:card_id>")
@login_required
def view_card(card_id):
    postcard = Postcard.query.get_or_404(card_id)
    sender = User.query.filter_by(login=postcard.sender_login).first_or_404()

    # Проверка прав доступа
    show_private = (
        current_user.login == postcard.sender_login
        or current_user.login == postcard.receiver_login
    )

    if postcard.is_private and not show_private:
        abort(403)

    # Проверка существования файла
    if not os.path.exists(os.path.join(app.static_folder, postcard.image_path)):
        app.logger.error(f"Файл открытки не найден: {postcard.image_path}")
        flash("Файл открытки повреждён или удалён")
        return redirect(url_for("main"))

    return render_template(
        "view_card.html", postcard=postcard, sender=sender, show_private=show_private
    )


@app.route("/download_card/<int:card_id>")
@login_required
def download_card(card_id):
    postcard = Postcard.query.get_or_404(card_id)

    # Проверка прав доступа
    if (
        current_user.login != postcard.sender_login
        and current_user.login != postcard.receiver_login
        and postcard.is_private
    ):
        abort(403)

    filepath = os.path.join(app.static_folder, postcard.image_path)
    if not os.path.exists(filepath):
        abort(404)

    filename = f"postcard_{postcard.id}.png"
    return send_from_directory(
        os.path.dirname(filepath),
        os.path.basename(filepath),
        as_attachment=True,
        download_name=filename,
    )


# Получение файла для скачивания
@app.route("/download/<filename>")
@login_required
def download_file(filename):
    return send_from_directory(
        os.path.join("static", "temp"), filename, as_attachment=True
    )


# Функция создания топика
def create_topic(login):
    admin_client = AdminClient({"bootstrap.servers": BROKER})

    metadata = admin_client.list_topics(timeout=10)
    # Проверяем, есть ли топик с именем login
    if not (login in metadata.topics):
        print(f"Топик '{login}' не существует, создаём...")
        new_topic = NewTopic(topic=login, num_partitions=1, replication_factor=1)
        admin_client.create_topics([new_topic]).get(login).result()
    else:
        print(f"Топик '{login}' уже существует")
    # print("++")


# Функция отправки сообщений
def send_messages(login, message):
    producer = Producer({"bootstrap.servers": BROKER})
    # for message in messages:
    producer.produce(topic=login, value=message.encode("utf-8"))
    producer.flush()
    # print("--")


# Вспомогательные функции
def generate_signature():
    adjectives = [
        "Великолепный",
        "Удивительный",
        "Невероятный",
        "Фантастический",
        "Волшебный",
    ]
    nouns = ["Друг", "Творец", "Художник", "Писатель", "Мечтатель"]
    numbers = random.randint(100, 999)
    return f"{random.choice(adjectives)} {random.choice(nouns)} #{numbers}"


def generate_famous_signature():
    famous_signatures = [
        "Микеланджело",
        "Рафаэль",
        "Айвазовский",
        "Леонардо да Винчи",
        "Ван Гог",
        "Пикассо",
        "Дали",
        "Рембрандт",
        "Моне",
        "Кандинский",
    ]
    return random.choice(famous_signatures)


def generate_token(login):
    KEY = bytes(
        [
            0x54,
            0x68,
            0x65,
            0x20,
            0x71,
            0x75,
            0x69,
            0x63,
            0x6B,
            0x20,
            0x62,
            0x72,
            0x6F,
            0x77,
            0x6E,
            0x20,
            0x66,
            0x6F,
            0x78,
            0x20,
            0x6A,
            0x75,
            0x6D,
            0x70,
            0x73,
            0x20,
            0x6F,
            0x76,
            0x65,
            0x72,
            0x20,
            0x6C,
        ]
    )

    NONCE = b"\x00" * 8

    plaintext = f"{login}".encode("utf-8")
    cipher = ChaCha20.new(key=KEY, nonce=NONCE)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext.hex()


def get_friends(login):
    friends = []
    # Друзья, где текущий пользователь - friend1
    friendships1 = Friend.query.filter(
        Friend.friend1_login == login, Friend.is_approved == True
    ).all()
    for f in friendships1:
        friend = User.query.filter_by(login=f.friend2_login).first()
        if friend:
            friends.append(friend)

    # Друзья, где текущий пользователь - friend2
    friendships2 = Friend.query.filter(
        Friend.friend2_login == login, Friend.is_approved == True
    ).all()
    for f in friendships2:
        friend = User.query.filter_by(login=f.friend1_login).first()
        if friend:
            friends.append(friend)

    return friends


def is_friend(login1, login2):
    if login1 == login2:
        return True

    friendship = Friend.query.filter(
        ((Friend.friend1_login == login1) & (Friend.friend2_login == login2))
        | ((Friend.friend1_login == login2) & (Friend.friend2_login == login1))
    ).first()

    return friendship and friendship.is_approved


def get_backgrounds():
    backgrounds = []
    for filename in os.listdir(app.config["UPLOAD_FOLDER"]):
        if filename.lower().endswith((".png", ".jpg", ".jpeg")):
            backgrounds.append(filename)
    return backgrounds


def create_card_image(front_text, background, font, color, pos_x, pos_y, font_size=24):
    try:
        # Загрузка фона
        app.logger.debug(f"Создание открытки с текстом: {front_text}")
        bg_path = os.path.join(app.config["UPLOAD_FOLDER"], background)
        if not os.path.exists(bg_path):
            raise FileNotFoundError(f"Фон {bg_path} не найден")

        img = Image.open(bg_path).convert("RGBA")

        FONTS_DIR = os.path.join(os.path.dirname(__file__), "static/fonts")

        font_map = {
            "Arial": os.path.join(
                FONTS_DIR, "arial.ttf"
            ),  # или LiberationSans-Regular.ttf
            "Times New Roman": os.path.join(
                FONTS_DIR, "times.ttf"
            ),  # или LiberationSerif-Regular.ttf
            "Courier New": os.path.join(
                FONTS_DIR, "cour.ttf"
            ),  # или LiberationMono-Regular.ttf
        }

        # Загрузка шрифта
        font_path = font_map.get(font, font_map["Arial"])  # По умолчанию Arial

        try:
            font_obj = ImageFont.truetype(font_path, font_size)
        except OSError:
            # Если шрифт не найден, используем встроенный
            font_obj = ImageFont.load_default()
            app.logger.warning(f"Шрифт {font_path} не найден, используется стандартный")

        # Рисуем текст
        draw = ImageDraw.Draw(img)
        draw.text((int(pos_x), int(pos_y)), front_text, fill=color, font=font_obj)

        # img = add_signature(img, current_user.postcard_signature)

        return img
    except Exception as e:
        app.logger.error(f"Ошибка при создании открытки: {str(e)}")
        raise


def add_signature(img, message):
    return img


@app.template_filter("b64encode")
def b64encode_filter(data):
    return base64.b64encode(data).decode("utf-8")


# Создание базы данных
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
