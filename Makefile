server: server.c list.c utils.c
	gcc server.c list.c utils.c -o server -lcrypto

client: client.c list.c utils.c
	gcc client.c list.c utils.c -o client -lcrypto

test: test.c menu.c crypto.c
	gcc test.c menu.c crypto.c -o test -lcrypto