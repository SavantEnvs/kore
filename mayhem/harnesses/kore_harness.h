/*
 * Shared scaffolding for the in-process kore harnesses (Mayhem integration).
 *
 * kore is an application server: untrusted bytes arrive on a listening socket and
 * flow through kore_connection_accept() -> c->handle() (net_recv / http_header_recv /
 * websocket_recv_*) -> http_process() -> the route's handler. These helpers bring kore
 * up the way main() + kore_worker_entry() do (single process, no fork, no privsep),
 * listening on a Linux abstract unix socket (no file on disk, no network port), and
 * deliver one input over a fresh client connection.
 *
 * State kept across inputs on purpose: the parsed configuration (servers, domains,
 * routes, validators, auth blocks), kore's pools and the fileref cache of the read-only
 * filemap files. Every connection and request an input creates is disconnected and
 * pruned before the next input, so each input's result depends only on that input.
 */
#ifndef KORE_MAYHEM_HARNESS_H
#define KORE_MAYHEM_HARNESS_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "kore.h"
#include "http.h"

static struct listener	*kh_listener;
static char		 kh_sockpath[108];

/* Bring kore up with the given configuration text (a "%d" is replaced by the pid). */
static void
kh_init(const char *conf_fmt)
{
	char			*conf;
	size_t			 len;
	FILE			*fp;
	struct kore_server	*srv;

	kore_quiet = 1;
	kore_foreground = 1;
	skip_runas = 1;
	skip_chroot = 1;

	kore_mem_init();
	kore_msg_init();
	kore_log_init();
	kore_tls_init();
	kore_pid = getpid();
	LIST_INIT(&kore_servers);

	kore_platform_init();
	http_parent_init();
	kore_auth_init();
	kore_validator_init();
	kore_filemap_init();
	kore_domain_init();
	kore_module_init();
	/* Handlers named in the config resolve with dlsym() on this binary (-rdynamic). */
	kore_module_load(NULL, NULL, KORE_MODULE_NATIVE);

	len = strlen(conf_fmt) + 4096;
	if ((conf = malloc(len)) == NULL)
		abort();
	snprintf(kh_sockpath, sizeof(kh_sockpath), "@kore-mayhem-%d", (int)getpid());
	snprintf(conf, len, conf_fmt, (int)getpid());
	if ((fp = fmemopen(conf, strlen(conf), "r")) == NULL)
		abort();
	kore_parse_config_file(fp);
	fclose(fp);
	free(conf);

	/* No access log: the worker-side accesslog buffer only exists in real workers. */
	kore_domain_closelogs();
	net_init();
	kore_connection_init();
	kore_platform_event_init();
	http_init();
	kore_filemap_resolve_paths();
	kore_timer_init();
	kore_fileref_init();

	srv = LIST_FIRST(&kore_servers);
	if (srv == NULL || (kh_listener = LIST_FIRST(&srv->listeners)) == NULL) {
		fprintf(stderr, "kore harness: no listener configured\n");
		abort();
	}
}

static int
kh_connect(void)
{
	struct sockaddr_un	sun;
	int			fd;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		abort();
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	memcpy(sun.sun_path, kh_sockpath, strlen(kh_sockpath));
	sun.sun_path[0] = '\0';
	if (connect(fd, (struct sockaddr *)&sun,
	    sizeof(sun.sun_family) + strlen(kh_sockpath)) == -1) {
		perror("kore harness: connect");
		abort();
	}
	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
		abort();
	return (fd);
}

/*
 * Send pre (fixed) then data (the input) to kore over one connection, letting kore
 * read, parse and respond as it goes. data is only sent once kore has answered pre
 * (e.g. the WebSocket upgrade), so it arrives as a separate read and is not swallowed
 * by the HTTP header parser. The server's replies are appended to out
 * (when out != NULL, up to outlen-1 bytes, NUL-terminated); returns the reply length.
 */
static size_t
kh_exchange(const u_int8_t *pre, size_t prelen, const u_int8_t *data,
    size_t len, char *out, size_t outlen)
{
	struct connection	*c = NULL;
	char			 rb[4096];
	ssize_t			 r;
	size_t			 total, sent, got, idle;
	int			 fd, shut, i, wait_pre, replied;
	const u_int8_t		*p;

	fd = kh_connect();
	if (!kore_connection_accept(kh_listener, &c) || c == NULL) {
		close(fd);
		return (0);
	}

	total = prelen + len;
	sent = 0;
	got = 0;
	shut = 0;
	idle = 0;
	wait_pre = (prelen > 0 && len > 0);
	replied = 0;
	if (out != NULL && outlen > 0)
		out[0] = '\0';

	for (i = 0; i < 100000 && idle < 4; i++) {
		size_t before = sent;

		if (wait_pre && sent == prelen && (replied || i > 64))
			wait_pre = 0;

		while (sent < total && !(wait_pre && sent >= prelen)) {
			size_t n;
			if (sent < prelen) {
				p = pre + sent;
				n = prelen - sent;
			} else {
				p = data + (sent - prelen);
				n = total - sent;
			}
			r = write(fd, p, n);
			if (r <= 0)
				break;
			sent += (size_t)r;
		}
		if (sent == total && !shut) {
			shutdown(fd, SHUT_WR);
			shut = 1;
		}

		c->evt.flags |= KORE_EVENT_READ | KORE_EVENT_WRITE;
		if (c->state != CONN_STATE_DISCONNECTING && !c->handle(c))
			kore_connection_disconnect(c);
		http_process();

		while ((r = read(fd, rb, sizeof(rb))) > 0) {
			replied = 1;
			if (out != NULL && got + 1 < outlen) {
				size_t n = (size_t)r;
				if (n > outlen - 1 - got)
					n = outlen - 1 - got;
				memcpy(out + got, rb, n);
				got += n;
				out[got] = '\0';
			}
		}

		if (c->state == CONN_STATE_DISCONNECTING)
			break;
		if (shut && sent == before)
			idle++;
		(void)before;
	}

	kore_connection_disconnect(c);
	kore_connection_prune(KORE_CONNECTION_PRUNE_DISCONNECT);
	/* Run any request that was still pending so it is freed with its connection. */
	http_process();
	close(fd);
	return (got);
}

#endif
