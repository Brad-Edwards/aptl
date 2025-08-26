#!/bin/bash
docker compose stop minetest-client
docker compose rm -f minetest-client
docker compose up --build -d minetest-client