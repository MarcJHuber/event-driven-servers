tactester is my previously private AAA client for testing TACACS+ and RADIUS
server implementations. This is unfinished code that may break with or without
notice, and it may not even compile.

Supposedly working protocols:

- TACACS+
  - TCP
  - TLS
- RADIUS
  - UDP
  - TCP
  - DTLS
  - TLS
- RADIUS/1.1
  - DTLS
  - TLS

Have a look at sample/tactester.cfg for server configuration details.

This isn't production code and not part of the standard build process, but it might
evolve.

I'll try to handle bug reports as usual, which basically means "best effort".

Cheers,

  Marc
