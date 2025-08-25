Run "make" to create demo certificates for (D)TLS testing.

Sample server configuration: ../tac_plus-ng-tls.cfg 

IOS-XE configuration hints:

! Cert chain installation:
crypto pki import demo pk sftp://user@192.0.2.10/democa/client.p12 pass secret

! Trustpoint ajustments
crypto pki trustpoint demo
 revocation-check none
crypto pki trustpoint demo-rrr1
 revocation-check none

! AAA server examples

tacacs server tacacs-tls
 address ipv4 192.0.2.11
 single-connection
 tls port 300
 tls trustpoint client demo
 tls trustpoint server demo
 tls match-server-identity dns-id server.demo.local
aaa group server tacacs+ tacacs-tls
 server name tacacs-tls

radius server radius-dtls
 address ipv4 192.0.2.12
 dtls port 2083
 dtls trustpoint client demo
 dtls trustpoint server demo
 dtls match-server-identity hostname server.demo.local
aaa group server radius radius-dtls
 server name radius-dtls

radius server radius-tls
 address ipv4 192.0.2.13
 tls port 2083
 tls trustpoint client demo
 tls trustpoint server demo
 tls match-server-identity hostname server.demo.local
aaa group server radius radius-tls
 server name radius-tls

tacacs server tacacs-tcp
 address ipv4 192.0.2.14
 single-connection
 key demo
 port 49
 single-connection
aaa group server tacacs+ tacacs-tcp
 server name tacacs-tcp

radius server radius-udp
 address ipv4 192.0.2.15 auth-port 1812 acct-port 1813
 key demo
aaa group server radius radius-udp
 server name radius-udp

