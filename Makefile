FLAGS=-Wall -Wextra -Werror -g
all:
	gcc $(FLAGS) -o dns dns.c
.PHONY: clean run test

clean:
	-rm dns

run: all
	./dns -p 5300 -s 8.8.8.8 -f big_filter

test: all
	sh tests/tests.sh