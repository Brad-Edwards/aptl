#!/bin/bash
docker compose stop victim
docker compose rm -f victim
docker compose up --build -d victim