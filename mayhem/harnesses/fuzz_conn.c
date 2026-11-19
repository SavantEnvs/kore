/*
 * kore connection harness (Mayhem integration): one input = the raw bytes a client
 * sends on one connection. Built three times:
 *
 *   -DFUZZ_HTTP       the input is an HTTP request stream; routes exercise query string,
 *                     cookies, urlencoded + multipart forms, validators (regex and
 *                     function), cookie authentication, redirects and returns.
 *   -DFUZZ_WEBSOCKET  a fixed, valid WebSocket upgrade request is sent first; the input
 *                     follows on the same connection as WebSocket frames (echoed back).
 *   -DFUZZ_FILEMAP    the input is an HTTP request stream against a filemap route that
 *                     serves a small read-only directory made under $TMPDIR at start-up.
 */
#include <sys/stat.h>

#include "kore_harness.h"

int	page(struct http_request *);
int	page_private(struct http_request *);
int	page_ws(struct http_request *);
/* Validators get the exact type kore's native runtime calls them through (runtime.c). */
int	v_func(struct http_request *, const void *);
int	v_session(struct http_request *, const void *);
void	ws_connect(struct connection *);
void	ws_message(struct connection *, u_int8_t, const void *, size_t);
void	ws_disconnect(struct connection *);

int	LLVMFuzzerTestOneInput(const u_int8_t *, size_t);

int
v_func(struct http_request *req, const void *data)
{
	(void)req;
	return (data != NULL && strlen((const char *)data) < 32 ? KORE_RESULT_OK :
	    KORE_RESULT_ERROR);
}

int
v_session(struct http_request *req, const void *data)
{
	(void)req;
	return (data != NULL && !strcmp((const char *)data, "letmein") ? KORE_RESULT_OK :
	    KORE_RESULT_ERROR);
}

int
page(struct http_request *req)
{
	struct http_file	*f;
	struct kore_buf		*out;
	char			*s, buf[256];
	const char		*h;
	int64_t			 i64;
	u_int16_t		 u16;
	ssize_t			 r;
	size_t			 len;

	http_populate_qs(req);
	http_populate_cookies(req);
	if (req->method == HTTP_METHOD_POST || req->method == HTTP_METHOD_PUT ||
	    req->method == HTTP_METHOD_PATCH) {
		if (http_request_header(req, "content-type", &h) &&
		    strstr(h, "multipart/form-data") != NULL)
			http_populate_multipart_form(req);
		else
			http_populate_post(req);
	}

	out = kore_buf_alloc(128);
	if (http_argument_get_string(req, "id", &s))
		kore_buf_appendf(out, "id=%s\n", s);
	if (http_argument_get_int64(req, "n", &i64))
		kore_buf_appendf(out, "n=%lld\n", (long long)i64);
	if (http_argument_get_uint16(req, "port", &u16))
		kore_buf_appendf(out, "port=%u\n", u16);
	if (http_request_cookie(req, "sid", &s))
		kore_buf_appendf(out, "sid=%s\n", s);
	if ((f = http_file_lookup(req, "file")) != NULL) {
		len = 0;
		while ((r = http_file_read(f, buf, sizeof(buf))) > 0)
			len += (size_t)r;
		kore_buf_appendf(out, "file=%s:%zu\n", f->filename, len);
	}
	if (req->http_body != NULL) {
		while ((r = http_body_read(req, buf, sizeof(buf))) > 0)
			kore_buf_append(out, buf, (size_t)r);
	}

	http_response_header(req, "content-type", "text/plain");
	http_response(req, HTTP_STATUS_OK, out->data, out->offset);
	kore_buf_free(out);
	return (KORE_RESULT_OK);
}

int
page_private(struct http_request *req)
{
	http_response(req, HTTP_STATUS_OK, "private", 7);
	return (KORE_RESULT_OK);
}

void
ws_connect(struct connection *c)
{
	(void)c;
}

void
ws_message(struct connection *c, u_int8_t op, const void *data, size_t len)
{
	kore_websocket_send(c, op, data, len);
}

void
ws_disconnect(struct connection *c)
{
	(void)c;
}

int
page_ws(struct http_request *req)
{
	kore_websocket_handshake(req, "ws_connect", "ws_message",
	    "ws_disconnect");
	return (KORE_RESULT_OK);
}

static const char *conf_common =
    "server s {\n\tunix @kore-mayhem-%d\n\ttls no\n}\n"
    "workers 1\n"
    "seccomp_tracing no\n"
    "http_server_version kore\n";

#if defined(FUZZ_FILEMAP) || defined(FUZZ_SELFTEST)
static char	filemap_dir[256];

static void
mkfile(const char *name, const char *content)
{
	char	path[512];
	FILE	*fp;

	snprintf(path, sizeof(path), "%s/%s", filemap_dir, name);
	if ((fp = fopen(path, "w")) == NULL)
		abort();
	fputs(content, fp);
	fclose(fp);
}

static void
make_filemap_dir(void)
{
	const char	*tmp;
	char		 sub[512];

	if ((tmp = getenv("TMPDIR")) == NULL || *tmp == '\0')
		tmp = "/tmp";
	snprintf(filemap_dir, sizeof(filemap_dir), "%s/kore-filemap-XXXXXX", tmp);
	if (mkdtemp(filemap_dir) == NULL)
		abort();
	mkfile("index.html", "<html>index</html>\n");
	mkfile("a.txt", "hello from a.txt\n");
	mkfile("page.html", "<p>page</p>\n");
	snprintf(sub, sizeof(sub), "%s/sub", filemap_dir);
	if (mkdir(sub, 0755) == -1)
		abort();
	mkfile("sub/index.html", "<html>sub</html>\n");
	mkfile("sub/style.css", "body{}\n");
}
#endif

#define CONF_HTTP_GLOBAL \
	"validator v_id regex ^[a-z0-9]*$\n" \
	"validator v_num regex ^-?[0-9]*$\n" \
	"validator v_func function v_func\n" \
	"validator v_session function v_session\n" \
	"authentication auth_cookie {\n" \
	"\tauthentication_type cookie\n" \
	"\tauthentication_value session\n" \
	"\tauthentication_validator v_session\n" \
	"\tauthentication_uri /login\n" \
	"}\n" \
	"authentication auth_header {\n" \
	"\tauthentication_type header\n" \
	"\tauthentication_value x-token\n" \
	"\tauthentication_validator v_session\n" \
	"}\n"

#define CONF_HTTP_ROUTES \
	"\tredirect ^/old/(.*)$ 301 /new/$1\n" \
	"\treturn ^/gone$ 410\n" \
	"\troute / {\n\t\thandler page\n" \
	"\t\tmethods get post put delete head patch options\n\t}\n" \
	"\troute ^/api/.*$ {\n\t\thandler page\n" \
	"\t\tmethods get post put patch\n" \
	"\t\tvalidate get id v_id\n" \
	"\t\tvalidate get n v_num\n" \
	"\t\tvalidate get port v_num\n" \
	"\t\tvalidate post id v_id\n" \
	"\t\tvalidate post name v_func\n" \
	"\t\tvalidate post file v_func\n\t}\n" \
	"\troute /private {\n\t\thandler page_private\n" \
	"\t\tauthenticate auth_cookie\n\t}\n" \
	"\troute /token {\n\t\thandler page_private\n" \
	"\t\tauthenticate auth_header\n\t}\n"

#define CONF_WS_ROUTES \
	"\troute /ws {\n\t\thandler page_ws\n\t\tmethods get\n\t}\n"

static void
init(void)
{
	static char	conf[8192];

#if defined(FUZZ_HTTP)
	snprintf(conf, sizeof(conf), "%s%s", conf_common, CONF_HTTP_GLOBAL
	    "domain * {\n\tattach s\n" CONF_HTTP_ROUTES "}\n");
#elif defined(FUZZ_WEBSOCKET)
	snprintf(conf, sizeof(conf), "%s%s", conf_common,
	    "websocket_maxframe 65536\n"
	    "domain * {\n\tattach s\n" CONF_WS_ROUTES "}\n");
#elif defined(FUZZ_FILEMAP)
	make_filemap_dir();
	snprintf(conf, sizeof(conf), "%sfilemap_index index.html\n"
	    "filemap_ext .html\n"
	    "domain * {\n\tattach s\n"
	    "\tfilemap / %s\n"
	    "\tfilemap /static/ %s/sub\n"
	    "}\n", conf_common, filemap_dir, filemap_dir);
#elif defined(FUZZ_SELFTEST)
	/* Every route of the three fuzz configurations in one server, for the oracle. */
	make_filemap_dir();
	snprintf(conf, sizeof(conf), "%s%sfilemap_index index.html\n"
	    "filemap_ext .html\n"
	    "websocket_maxframe 65536\n"
	    "domain * {\n\tattach s\n" CONF_HTTP_ROUTES CONF_WS_ROUTES
	    "\tfilemap /files/ %s\n"
	    "\tfilemap /static/ %s/sub\n"
	    "}\n", conf_common, CONF_HTTP_GLOBAL, filemap_dir, filemap_dir);
#else
#error "build with -DFUZZ_HTTP, -DFUZZ_WEBSOCKET, -DFUZZ_FILEMAP or -DFUZZ_SELFTEST"
#endif
	kh_init(conf);
}

#if !defined(FUZZ_SELFTEST)
int
LLVMFuzzerTestOneInput(const u_int8_t *data, size_t len)
{
#if defined(FUZZ_WEBSOCKET)
	static const char upgrade[] =
	    "GET /ws HTTP/1.1\r\n"
	    "Host: localhost\r\n"
	    "Upgrade: websocket\r\n"
	    "Connection: Upgrade\r\n"
	    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
	    "Sec-WebSocket-Version: 13\r\n"
	    "\r\n";
#endif

	if (kh_listener == NULL)
		init();

#if defined(FUZZ_WEBSOCKET)
	kh_exchange((const u_int8_t *)upgrade, sizeof(upgrade) - 1, data, len,
	    NULL, 0);
#else
	kh_exchange(NULL, 0, data, len, NULL, 0);
#endif
	return (0);
}
#endif /* !FUZZ_SELFTEST */
