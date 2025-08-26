#!/bin/bash
docker compose stop minetest-server
docker compose rm -f minetest-server
docker compose up --build -d minetest-server