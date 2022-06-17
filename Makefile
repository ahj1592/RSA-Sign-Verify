server: server.c list.c
	gcc server.c list.c -o server

client: client.c list.c
	gcc client.c list.c -o client

test: test.c menu.c crypto.c
	gcc test.c menu.c crypto.c -o test -lcrypto