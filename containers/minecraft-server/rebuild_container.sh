#!/bin/bash
docker compose stop minecraft-server
docker compose rm -f minecraft-server
docker compose up --build -d minecraft-server