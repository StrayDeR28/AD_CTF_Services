#!/bin/bash

# Остановка Docker Compose и удаление томов
echo "Остановка Docker Compose и удаление томов..."
docker compose down -v

# Удаление папки instance с учётом прав доступа
echo "Удаление папки instance..."
if [ -d instance ]; then
    sudo rm -rf instance && echo "Папка instance удалена" || {
        echo "Ошибка удаления instance. Попробуем изменить права..."
        sudo chmod -R 777 instance 2>/dev/null
        sudo rm -rf instance && echo "Папка instance удалена после изменения прав" || {
            echo "Не удалось удалить папку instance. Попробуйте вручную."
            exit 1
        }
    }
else
    echo "Папка instance не найдена"
fi

# Удаление папки __pycache__ с учётом прав доступа
echo "Удаление папки __pycache__..."
if [ -d __pycache__ ]; then
    sudo rm -rf __pycache__ && echo "Папка __pycache__ удалена" || {
        echo "Ошибка удаления __pycache__. Попробуем изменить права..."
        sudo chmod -R 777 __pycache__ 2>/dev/null
        sudo rm -rf __pycache__ && echo "Папка __pycache__ удалена после изменения прав" || {
            echo "Не удалось удалить __pycache__. Попробуйте вручную."
            exit 1
        }
    }
else
    echo "Папка __pycache__ не найдена"
fi

# Очистка сгенерированных файлов
echo "Очистка сгенерированных файлов..."
rm -rf static/postcards/* 2>/dev/null || echo "Папка static/postcards пуста или отсутствует"
#rm -rf static/images/backgrounds/* 2>/dev/null || echo "Папка static/images/backgrounds пуста или отсутствует"

# Удаление томов Redpanda
# echo "Удаление томов Redpanda..."
# docker volume prune -f

# Удаление образов
# echo "Удаление образов..."
# docker rmi -f rayonpostling-web rayonpushling-app rayonpostling-app 2>/dev/null || echo "Некоторые образы уже удалены"
# docker image prune -a -f

# Очистка кэша сборки
# echo "Очистка кэша сборки..."
# docker builder prune -a -f

echo -e "Очистка завершена! Можно запускать:\n* если меняли код, докер или еще что 	docker compose up --build\n* если хотите начать с чистого листа	docker compose up\n"
