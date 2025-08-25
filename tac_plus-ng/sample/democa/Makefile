all: root.crt

clean:
	@rm -rf *.key *.crt *.csr serial* index* *.srl *.pem *.p12

%.key:
	openssl genpkey -quiet -algorithm RSA -out $@

%.csr: %.key %.cnf
	openssl req -batch -new -key $< -config $(word 2,$^) -out $@

root.crt: root.key root.cnf
	openssl req -batch -config $(word 2,$^) -key $< -new -x509 -days 3650 -sha256 -extensions v3_ca -out $@

intermediate.crt: intermediate.csr root.crt
	openssl x509 -req -in $< -CA root.crt -CAkey root.key -CAcreateserial \
		-days 3650 -extfile intermediate.cnf -extensions v3_intermediate_ca -out $@

server.crt: server.csr intermediate.csr
	openssl x509 -req -in $< -CA intermediate.crt -CAkey intermediate.key -CAcreateserial \
		-days 365 -extfile server.cnf -extensions server_cert -out $@

client.crt: client.csr intermediate.csr
	openssl x509 -req -in $< -CA intermediate.crt -CAkey intermediate.key -CAcreateserial \
		-days 365 -extfile client.cnf -extensions client_cert -out $@

client-chain.pem: client.crt intermediate.crt root.crt
	cat $^ > $@

server-chain.pem: server.crt intermediate.crt root.crt
	cat $^ > $@

client.p12: client-chain.pem client.key
	openssl pkcs12 -export -out $@ -inkey $(word 2,$^) -in $< -password pass:secret

all: intermediate.crt server.key intermediate.key server-chain.pem client.p12

