#!/bin/sh

GOODDOMAINLIST="./tests/good_domains"
BADDOMAINLIST="./tests/bad_domains"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

printf "RUNNING SERVER \"./dns -s 8.8.8.8 -f tests/filter -p 5300\"\n"
./dns -s 8.8.8.8 -f tests/filter -p 5300 & pid=$!
sleep 1

printf "________________________________________________________________\n"
printf "                      TESTING GOOD DOMAINS                      \n"
printf "________________________________________________________________\n"
printf "\n"

while read DOMAIN; do
    echo "RUNNING \"dig -p 5300 @127.0.0.1 +short $DOMAIN\""
    address=$(dig -p 5300 @127.0.0.1 +short "$DOMAIN" | head -1)
    if [ -z "$address" ]
    then
    printf "${RED}TEST FAILED${NC} - no address received\n"
    else
    printf "${GREEN}TEST PASSED${NC} - received ${address}\n"
    fi
done < "$GOODDOMAINLIST"

printf "________________________________________________________________\n"
printf "                      TESTING BAD DOMAINS                       \n"
printf "________________________________________________________________\n"
printf "\n"

while read DOMAIN; do
    echo "RUNNING \"dig -p 5300 @127.0.0.1 +short $DOMAIN\""
    address=$(dig -p 5300 @127.0.0.1 +short "$DOMAIN" | head -1)
    if [ -z "$address" ]
    then
    printf "${GREEN}TEST PASSED${NC} - no address received\n"
    else
    printf "${RED}TEST FAILED${NC} - expected nothing but received ${address}\n"
    fi
done < "$BADDOMAINLIST"

kill $pid