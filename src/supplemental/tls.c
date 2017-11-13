//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

#include "core/nng_impl.h"

#include "tls.h"

// NNG_TLS_MAX_SEND_SIZE limits the amount of data we will send "immediately",
// exerting backpressure if this size is exceeded.  This is also the size
// of the maximum TCP window, so we should avoid introducing extra latency
// caused by misalignment.
#ifndef NNG_TLS_MAX_SEND_SIZE
#define NNG_TLS_MAX_SEND_SIZE 65536
#endif

// NNG_TLS_MAX_RECV_SIZE limits the amount of data we will receive in a single
// operation.  As we have to buffer data, this drives the size of our
// intermediary buffer.
#ifndef NNG_TLX_MAX_RECV_SIZE
#define NNG_TLS_MAX_RECV_SIZE
#endif

struct nni_tls {
	nni_plat_tcp_pipe * tcp;
	mbedtls_ssl_context ctx;
	nni_mtx             lk;
	nni_aio *           tcp_send;
	nni_aio *           tcp_recv;
	bool                sending;
	bool                recving;
	bool                closed;
	bool                hsdone;
	char *              recvbuf;
	int                 recvidx;
	nni_list            sends;     // upper side sends
	nni_list            recvs;     // upper recv aios
	nni_aio *           handshake; // handshake aio (upper)
};

struct nni_tls_config {
	mbedtls_ssl_config cfg_ctx;
	bool               dbg;
#ifdef NNG_TLS_USE_CTR_DRBG
	mbedtls_ctr_drbg_context rng_ctx;
	nni_mtx                  rng_lk;
#endif
};

extern int nni_tls_init(nni_tls **, nni_tls_config *, nni_plat_tcp_pipe *);

extern void nni_tls_close(nni_tls *);
extern void nni_tls_fini(nni_tls *);
extern void nni_tls_send(nni_tls *, nni_aio *);
extern void nni_tls_recv(nni_tls *, nni_aio *);

static void nni_tls_send_cb(void *);
static void nni_tls_recv_cb(void *);

static void nni_tls_do_send(nni_tls *);
static void nni_tls_do_handshake(nni_tls *);

static void
nni_tls_dbg(void *ctx, int level, const char *file, int line, const char *s)
{
	char            buf[128];
	nni_tls_config *cfg = ctx;

	if (cfg->dbg) {
		snprintf(buf, sizeof(buf), "%s:%04d: %s", file, line, s);
		nni_plat_println(buf);
	}
}

static int
nni_tls_get_entropy(void *arg, unsigned char *buf, size_t len)
{
	NNI_ARG_UNUSED(arg);
	while (len) {
		uint32_t x = nni_random();
		size_t   n;

		n = len < sizeof(x) ? len : sizeof(x);
		memcpy(buf, &x, n);
		len -= n;
		buf += n;
	}
	return (0);
}

static int
nni_tls_random(void *arg, unsigned char *buf, size_t sz)
{
#ifdef NNG_TLS_USE_CTR_DRBG
	int             rv;
	nni_tls_config *cfg = arg;
	NNI_ARG_UNUSED(arg);

	nni_mtx_lock(&cfg->rng_lk);
	rv = mbedtls_ctr_drbg_random(&cfg->rng_ctx, buf, sz);
	nni_mtx_unlock(&cfg->rng_lk);
	return (rv);
#else
	return (nni_tls_get_entropy(arg, buf, sz));
#endif
}

void
nni_tls_config_fini(nni_tls_config *cfg)
{
	mbedtls_ssl_config_free(&cfg->cfg_ctx);
#ifdef NNG_TLS_USE_CTR_DRBG
	mbedtls_ctr_drbg_free(&cfg->rng_ctx);
#endif
	NNI_FREE_STRUCT(cfg);
}

int
nni_tls_config_init(nni_tls_config **cpp, int mode)
{
	nni_tls_config *cfg;
	int             rv;
	int             sslmode;

	if ((cfg = NNI_ALLOC_STRUCT(cfg)) == NULL) {
		return (NNG_ENOMEM);
	}

	if (mode == NNI_TLS_CONFIG_SERVER) {
		sslmode = MBEDTLS_SSL_IS_SERVER;
	} else {
		sslmode = MBEDTLS_SSL_IS_CLIENT;
	}

	mbedtls_ssl_config_init(&cfg->cfg_ctx);
	rv = mbedtls_ssl_config_defaults(&cfg->cfg_ctx, sslmode,
	    MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (rv != 0) {
		nni_tls_config_fini(cfg);
		return (rv);
	}

#ifdef NNG_TLS_USE_CTR_DRBG
	mbedtls_ctr_drbg_init(&cfg->rng_ctx);
	rv = mbedtls_ctr_drbg_seed(
	    &cfg->rng_ctx, nni_tls_get_entropy, NULL, NULL, 0);
	if (rv != 0) {
		nni_tls_config_fini(cfg);
		return (rv);
	}
#endif
	mbedtls_ssl_conf_rng(&cfg->cfg_ctx, nni_tls_random, cfg);

	// XXX: We have to fix this.
	mbedtls_ssl_conf_authmode(&cfg->cfg_ctx, MBEDTLS_SSL_VERIFY_NONE);

	mbedtls_ssl_conf_dbg(&cfg->cfg_ctx, nni_tls_dbg, cfg);

	*cpp = cfg;
	return (0);
}

void
nni_tls_fini(nni_tls *tp)
{
	nni_aio_stop(tp->tcp_send);
	nni_aio_stop(tp->tcp_recv);
	nni_aio_fini(tp->tcp_send);
	nni_aio_fini(tp->tcp_recv);
	mbedtls_ssl_free(&tp->ctx);
	nni_mtx_fini(&tp->lk);
	NNI_FREE_STRUCT(tp);
}

void
nni_tls_strerror(int errnum, char *buf, size_t sz)
{
	if (errnum & NNG_ETRANERR) {
		errnum &= ~NNG_ETRANERR;
		errnum = -errnum;

		mbedtls_strerror(errnum, buf, sz);
	} else {
		(void) snprintf(buf, sz, "%s", nng_strerror(errnum));
	}
}

// nni_tls_mkerr converts an mbed error to an NNG error.  In all cases
// we just encode with NNG_ETRANERR.
static int
nni_tls_mkerr(int err)
{
	err = -err;
	err |= NNG_ETRANERR;
	return (err);
}

int
nni_tls_init(nni_tls **tpp, nni_tls_config *cfg, nni_plat_tcp_pipe *tcp)
{
	nni_tls *tp;
	int      rv;

	if ((tp = NNI_ALLOC_STRUCT(tp)) == NULL) {
		return (NNG_ENOMEM);
	}

	nni_aio_list_init(&tp->sends);
	nni_aio_list_init(&tp->recvs);
	nni_mtx_init(&tp->lk);
	mbedtls_ssl_init(&tp->ctx);

	tp->tcp = tcp;

	if (((rv = nni_aio_init(&tp->tcp_send, nni_tls_send_cb, tp)) != 0) ||
	    ((rv = nni_aio_init(&tp->tcp_recv, nni_tls_recv_cb, tp)) != 0)) {
		nni_tls_fini(tp);
		return (rv);
	}

	*tpp = tp;
	return (0);
}

static void
nni_tls_cancel(nni_aio *aio, int rv)
{
	nni_tls *tp = aio->a_prov_data;
	nni_mtx_lock(&tp->lk);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	// XXX: cancel the underlying TCP send/recv as well?
	nni_mtx_unlock(&tp->lk);
}

// nni_tls_send_cb is called when the underlying TCP send completes.
static void
nni_tls_send_cb(void *ctx)
{
	nni_tls *tp = ctx;

	nni_mtx_lock(&tp->lk);
	tp->sending = 0;
	if (tp->handshake != NULL) {
		nni_tls_do_handshake(tp);
	} else if (!nni_list_empty(&tp->sends)) {
		nni_tls_do_send(tp);
	}
	nni_mtx_unlock(&tp->lk);
}

static void
nni_tls_recv_cb(void *ctx)
{
	nni_tls *tp = ctx;

	nni_mtx_lock(&tp->lk);
	tp->recving = 0;
	if (tp->handshake != NULL) {
		nni_tls_do_handshake(tp);
	} else if (!nni_list_empty(&tp->recvs)) {
		nni_tls_do_recv(tp);
	}
	nni_mtx_unlock(&tp->lk);
}

// This handles the bottom half send (i.e. sending over TCP).
// We always accept a chunk of data, to a limit, if the bottom
// sender is not busy.  Then we handle that in the background.
// If the sender *is* busy, we return MBEDTLS_ERR_SSL_WANT_WRITE.
// The chunk size we accept is 64k at a time, which prevents
// ridiculous over queueing.  This is always called with the pipe
// lock held, and never blocks.
static int
nni_tls_net_send(void *ctx, const unsigned char *buf, size_t len)
{
	nni_tls *tp = ctx;

	if (len > NNG_TLS_MAX_SEND_SIZE) {
		len = NNG_TLS_MAX_SEND_SIZE;
	}
	// We should already be running with the pipe lock held,
	// as we are running in that context.
	if (tp->sending) {
		return (MBEDTLS_ERR_SSL_WANT_WRITE);
	}
	if (tp->closed) {
		return (MBEDTLS_ERR_NET_SEND_FAILED);
	}

	tp->sending                    = 1;
	tp->tcp_send->a_niov           = 1;
	tp->tcp_send->a_iov[0].iov_buf = (char *) buf;
	tp->tcp_send->a_iov[0].iov_len = len;
	nni_aio_set_timeout(tp->tcp_send, -1); // No timeout.
	nni_plat_tcp_pipe_send(tp->tcp, tp->tcp_send);
	return (len);
}

static int
nni_tls_net_recv(void *ctx, const unsigned char *buf, size_t len)
{
	nni_tls *tp = ctx;

	// We should already be running with the pipe lock held,
	// as we are running in that context.
	if (tp->recving) {
		return (MBEDTLS_ERR_SSL_WANT_READ);
	}
	if (tp->closed) {
		return (MBEDTLS_ERR_NET_SEND_FAILED);
	}

	tp->recving                    = 1;
	tp->tcp_recv->a_niov           = 1;
	tp->tcp_recv->a_iov[0].iov_buf = (char *) buf;
	tp->tcp_recv->a_iov[0].iov_len = len;
	nni_aio_set_timeout(tp->tcp_recv, -1); // No timeout.
	nni_plat_tcp_pipe_recv(tp->tcp, tp->tcp_recv);
	return (len);
}

// nni_tls_send is the exported send function.  It has a similar calling
// convention as the platform TCP pipe.
void
nni_tls_send(nni_tls *tp, nni_aio *aio)
{
	nni_mtx_lock(&tp->lk);
	if (nni_aio_start(aio, nni_tls_cancel, tp) != 0) {
		nni_mtx_unlock(&tp->lk);
		return;
	}
	if (!tp->hsdone) {
		nni_mtx_unlock(&tp->lk);
		nni_aio_finish_error(aio, NNG_ESTATE);
		return;
	}
	if (tp->closed) {
		nni_mtx_unlock(&tp->lk);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	nni_list_append(&tp->sends, aio);
	nni_tls_do_send(tp);
	nni_mtx_unlock(&tp->lk);
}

void
nni_tls_recv(nni_tls *tp, nni_aio *aio)
{
	nni_mtx_lock(&tp->lk);
	if (nni_aio_start(aio, nni_tls_cancel, tp) != 0) {
		nni_mtx_unlock(&tp->lk);
		return;
	}
	if (!tp->hsdone) {
		nni_mtx_unlock(&tp->lk);
		nni_aio_finish_error(aio, NNG_ESTATE);
		return;
	}
	if (tp->closed) {
		nni_mtx_unlock(&tp->lk);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	nni_list_append(&tp->recvs, aio);
	nni_tls_do_recv(tp);
	nni_mtx_unlock(&tp->lk);
}

// nni_tls_handshake makes a non-blocking attempt to complete the handshake.
void
nni_tls_do_handshake(nni_tls *tp)
{
	int      rv;
	nni_aio *aio = tp->handshake;

	if (aio == NULL) {
		return;
	}
	if (tp->closed) {
		tp->handshake = NULL;
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	rv = mbedtls_ssl_handshake(&tp->ctx);
	switch (rv) {
	case MBEDTLS_ERR_SSL_WANT_WRITE:
	case MBEDTLS_ERR_SSL_WANT_READ:
		// We have underlying I/O to complete first.  We will
		// be called again by a callback later.
		return;
	case 0:
		// The handshake is done, yay!
		tp->handshake = NULL;
		tp->hsdone    = 1;
		nni_aio_finish(aio, 0, 0);
		return;

	default:
		// Some other error occurred... would be nice to be
		// able to diagnose it better.
		tp->handshake = NULL;
		nni_aio_finish_error(aio, nni_tls_mkerr(rv));
		return;
	}
}

// nni_tls_do_send is called to try to send more data if we have not
// yet completed the I/O.  It also completes any transactions that *have*
// completed.  It must be called with the lock held.
static void
nni_tls_do_send(nni_tls *tp)
{
	nni_aio *aio;

	while ((aio = nni_list_first(&tp->sends)) != NULL) {
		int n;

		if (aio->a_niov == 0) {
			// No more I/O to complete.
			nni_aio_list_remove(aio);
			nni_aio_finish(aio, 0, aio->a_count);
			return;
		}
		if (aio->a_iov[0].iov_len == 0) {
			for (int i = 0; i < aio->a_niov; i++) {
				aio->a_iov[i] = aio->a_iov[i + 1];
			}
			aio->a_niov--;
			continue;
		}
		n = mbedtls_ssl_write(
		    &tp->ctx, aio->a_iov[0].iov_buf, aio->a_iov[0].iov_len);
		if (n >= 0) {
			aio->a_iov[0].iov_buf += n;
			aio->a_iov[0].iov_len -= n;
			aio->a_count += n;
			continue;
		}

		if (n == MBEDTLS_ERR_SSL_WANT_WRITE) {
			// Cannot send any more data right now, wait for
			// callback.
			return;
		}

		// Some other error occurred... this is not good.
		// Want better diagnostics.
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, nni_tls_mkerr(n));
	}
}

// nni_tls_do_recv is called to try to receive more data if we have not
// yet completed the I/O.  It also completes any transactions that *have*
// completed.  It must be called with the lock held.
static void
nni_tls_do_recv(nni_tls *tp)
{
	nni_aio *aio;

	while ((aio = nni_list_first(&tp->recvs)) != NULL) {
		int n;

		if (aio->a_niov == 0) {
			// No more I/O to complete.
			nni_aio_list_remove(aio);
			nni_aio_finish(aio, 0, aio->a_count);
			return;
		}
		if (aio->a_iov[0].iov_len == 0) {
			for (int i = 0; i < aio->a_niov; i++) {
				aio->a_iov[i] = aio->a_iov[i + 1];
			}
			aio->a_niov--;
			continue;
		}
		n = mbedtls_ssl_read(
		    &tp->ctx, aio->a_iov[0].iov_buf, aio->a_iov[0].iov_len);
		if (n >= 0) {
			aio->a_iov[0].iov_buf += n;
			aio->a_iov[0].iov_len -= n;
			aio->a_count += n;
			continue;
		}

		if (n == MBEDTLS_ERR_SSL_WANT_READ) {
			// Cannot receive any more data right now, wait for
			// callback.
			return;
		}

		// Some other error occurred... this is not good.
		// Want better diagnostics.
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, nni_tls_mkerr(n));
	}
}
