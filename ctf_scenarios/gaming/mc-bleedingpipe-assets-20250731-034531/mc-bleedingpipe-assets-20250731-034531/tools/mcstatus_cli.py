#!/usr/bin/env python3
from mcstatus import JavaServer
import sys
target = sys.argv[1] if len(sys.argv)>1 else "127.0.0.1:25565"
srv = JavaServer.lookup(target)
st = srv.status()
print("MOTD:", st.description)
print("Players:", st.players.online, "/", st.players.max)
