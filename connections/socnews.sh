#!/bin/bash
socat TCP-Listen:10063,bind=localhost,fork SOCKS4A:localhost:news.mixmin.net:563,socksport=9050 > /dev/null 2>&1 &