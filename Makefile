all: socks4server

socks4server: socks4server.c
	gcc $< -o $@
