FLAGS=-Wall -Wextra -Werror -g
all:
	gcc $(FLAGS) -o dns dns.c
.PHONY: clean
clean:
	-rm dns