#!/bin/bash

# Остановка Docker Compose и удаление томов
echo "Остановка Docker Compose и удаление томов..."
docker compose down -v

# Удаление базы данных
echo "Удаление базы данных..."
if [ -f instance/postcards.db ]; then
    rm instance/postcards.db
    echo "База данных удалена: instance/postcards.db"
else
    echo "База данных не найдена: instance/postcards.db"
fi

# Очистка сгенерированных файлов
echo "Очистка сгенерированных файлов..."
rm -rf static/postcards/* 2>/dev/null || echo "Папка static/postcards пуста или отсутствует"
#rm -rf static/images/backgrounds/* 2>/dev/null || echo "Папка static/images/backgrounds пуста или отсутствует"

# Удаление томов Redpanda
echo "Удаление томов Redpanda..."
docker volume prune -f

# Удаление образов
echo "Удаление образов..."
docker rmi -f rayonpostling-web rayonpushling-app rayonpostling-app 2>/dev/null || echo "Некоторые образы уже удалены"
docker image prune -a -f

# Очистка кэша сборки
echo "Очистка кэша сборки..."
docker builder prune -a -f

echo "Очистка завершена! Можно запускать: docker compose up --build"
