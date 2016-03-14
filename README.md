# TLSLayer

Single C file TLS 1.2 (also 1.1 and 1.0) implementation, using [libtomcrypt](https://github.com/libtom/libtomcrypt "libtomcrypt")  as crypto library. Before using tlslayer.c you should download and compile tomcrypt first. I'm working at an alternative efficient RSA encryption/decryption implementation, to allow the compilation, alternatively, without tomcrypt, on devices where memory and code size is an issue.

Compiling
----------

`$ gcc tlshello.c -o tlshello -ltomcrypt`  

For debuging tls connections, the DEBUG flag must be set:

`$ gcc tlsserverhello.c -o tlsserverhello -ltomcrypt`  


The entire library is a single c file that you just include in your source.

Usage
----------

You just 
`#include "tlslayer.c"`
in your code. Everithing is a single file.

Features
----------

The main feature of this implementation is the ability to serialize TLS context, via tls_export_context and re-import it, via tls_import_context in another pre-forked worker process (socket descriptor may be sent via sendmsg).

For now it supports TLS 1.2, TLS 1.1 + 1.0 (when TLS_LEGACY_SUPPORT is defined / default is on), RSA, DHE, ciphers:
`TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA256, TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_GCM_SHA384, TLS_DHE_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_RSA_WITH_AES_256_CBC_SHA, TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, TLS_DHE_RSA_WITH_AES_128_GCM_SHA256` and `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384`.

It has a low level interface, efficient for non-blocking, asynchronous sockets, and a blocking, libssl-style interface.

It implements all what is needed for the TLS protocol version 1.2 and a pem/der parser. From tomcrypt it uses RSA and AES(CBC) encryption/decryption, SHA1, SHA256, SHA384 and HMAC functions.

Now it supports client certificate. To request a client certificate, call ``tls_request_client_certificate(TLSContext *)`` following ``tls_accept(TLSContext *)``.

It implements SNI extension (Server Name Indication). To get the SNI string call ``tls_sni(TLSContext *)``.

This library was written to be used by my other projects [Concept Applications Server](https://github.com/Devronium/ConceptApplicationServer "Concept Application Server") and [Concept Native Client](https://github.com/Devronium/ConceptClientQT "Concept Client QT")

Examples
----------
1. [examples/tlsclienthello.c](https://github.com/eduardsui/tlslayer/blob/master/examples/tlsclienthello.c) simple client example
2. [examples/tlshelloworld.c](https://github.com/eduardsui/tlslayer/blob/master/examples/tlshelloworld.c) simple server example
3. [examples/tlssimple.c](https://github.com/eduardsui/tlslayer/blob/master/examples/tlssimple.c) simple blocking client using libssl-ish API
4. [examples/tlssimpleserver.c](https://github.com/eduardsui/tlslayer/blob/master/examples/tlssimpleserver.c) simple blocking server using libssl-ish API

After compiling the examples, in the working directory, you should put fullchain.pem and privkey.pem in a directory called testcert for running the server examples. I've used [letsencrypt](https://github.com/letsencrypt/letsencrypt) for certificate generation (is free!).

License
----------
Public domain, BSD, MIT. Choose one.
