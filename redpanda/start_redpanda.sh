#!/bin/bash
cd ~/oleg/service/AD_CTF_Services/redpanda
docker stop redpanda-1 2>/dev/null || true
docker rm redpanda-1 2>/dev/null || true
docker compose up -d
