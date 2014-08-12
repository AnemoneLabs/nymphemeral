#!/bin/bash
# Note: this script points to the smtp server on anemone.mooo.com. Therefore it will
# only accept messages to addresses at anemone.mooo.com or nym.now.im.
socat TCP-Listen:2526,bind=localhost,fork SOCKS4A:localhost:lnwxejysejqjlm3l.onion:2525,socksport=9050 > /dev/null 2>&1 &