#!/bin/bash
docker compose stop gaming-api
docker compose rm -f gaming-api
docker compose up --build -d gaming-api