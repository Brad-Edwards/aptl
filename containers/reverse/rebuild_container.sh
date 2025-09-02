#!/bin/bash
docker compose stop reverse
docker compose rm -f reverse
docker compose up --build -d reverse