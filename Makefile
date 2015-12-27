all: socks4server

socks4server: socks4server.c
	gcc $< -o $@

clean: 
	rm socks4server
