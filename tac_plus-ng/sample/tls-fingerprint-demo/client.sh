#!/bin/sh
openssl s_client -cert client.selfsigned.crt -key client.selfsigned.key -connect 127.0.0.1:4950
