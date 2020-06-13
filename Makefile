rhsplit: rhsplit.c list.h
	gcc -O2 -g -Werror -Wall -fstack-protector-strong -o rhsplit rhsplit.c -lcrypto -lz
