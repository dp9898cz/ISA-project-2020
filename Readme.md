# Filtrující DNS resolver - Projekt do ISA 2020
Tento program filtruje dotazy typu A směřující na domény v rámci dodaného seznamu a filtruje také jejich poddomény. Podporuje pouze komunikaci prostřednictvím protokolu UDP a dotazy typu A. Nepodporuje DNSSEC.

## Příklady spuštění

$ sudo ./dns -h
$ sudo ./dns -v -s 8.8.8.8 -f filter.txt
$ sudo ./dns -s 1.0.0.1 -f file
$ ./dns -p 5353 -s 1.1.1.1 -f blocked_addresses.txt

(sudo je zde kvůli otevření socketu na systémově chráněném portu 53)

## Přeložení programu

$ make

## Seznam odevzdaných souborů
1. dns.c
2. Makefile
3. dokumentace.pdf
4. README.md