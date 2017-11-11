//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_SUPPLEMENTAL_TLS_H
#define NNG_SUPPLEMENTAL_TLS_H

// nni_tls represents the context for a single TLS stream.
typedef struct nni_tls nni_tls;

// nni_tls_config is the context for full TLS configuration, normally
// associated with an endpoint, for example.
typedef struct nni_tls_config nni_tls_config;

#define NNI_TLS_CONFIG_SERVER 1
#define NNI_TLS_CONFIG_CLIENT 0

extern int  nni_tls_config_init(nni_tls_config **, int);
extern void nni_tls_config_fini(nni_tls_config *);

extern int  nni_tls_init(nni_tls **, nni_tls_config *, nni_plat_tcp_pipe *);
extern void nni_tls_close(nni_tls *);
extern void nni_tls_fini(nni_tls *);
extern void nni_tls_send(nni_tls *, nni_aio *);
extern void nni_tls_recv(nni_tls *, nni_aio *);
extern void nni_tls_handshake(nni_tls *, nni_aio *);
extern void nni_tls_strerror(int, char *, size_t); // review this

#endif // NNG_SUPPLEMENTAL_TLS_H
