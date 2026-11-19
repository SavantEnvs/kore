/*
 * kore functional self-test (Mayhem integration; the oracle mayhem/test.sh runs).
 *
 * kore ships no test suite, so this drives real client connections through kore's
 * request path (the same server, routes and handlers the fuzz targets use) and checks
 * known requests against known responses, plus known-answer checks for the JSON API
 * and the string decoders. Prints one "PASS <name>" / "FAIL <name>" line per check and
 * a final "SUMMARY passed=<p> failed=<f>" line.
 */
#include <stdarg.h>

#define FUZZ_SELFTEST 1
#include "fuzz_conn.c"

static int	passed, failed;
static char	resp[65536];

static void
result(const char *name, int ok, const char *detail)
{
	if (ok) {
		passed++;
		printf("PASS %s\n", name);
	} else {
		failed++;
		printf("FAIL %s\n", name);
		if (detail != NULL)
			printf("---- got ----\n%s\n-------------\n", detail);
	}
}

/* Send req; every NULL-terminated expected substring must appear in the reply. */
static void
http_case(const char *name, const char *req, ...)
{
	va_list		 ap;
	const char	*want;
	int		 ok = 1;

	kh_exchange(NULL, 0, (const u_int8_t *)req, strlen(req), resp,
	    sizeof(resp));
	va_start(ap, req);
	while ((want = va_arg(ap, const char *)) != NULL) {
		if (strstr(resp, want) == NULL)
			ok = 0;
	}
	va_end(ap);
	result(name, ok, resp);
}

/* As http_case, but the reply must NOT contain bad. */
static void
http_case_not(const char *name, const char *req, const char *want,
    const char *bad)
{
	kh_exchange(NULL, 0, (const u_int8_t *)req, strlen(req), resp,
	    sizeof(resp));
	result(name, strstr(resp, want) != NULL && strstr(resp, bad) == NULL,
	    resp);
}

static void
websocket_case(void)
{
	static const char upgrade[] =
	    "GET /ws HTTP/1.1\r\n"
	    "Host: localhost\r\n"
	    "Upgrade: websocket\r\n"
	    "Connection: Upgrade\r\n"
	    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
	    "Sec-WebSocket-Version: 13\r\n"
	    "\r\n";
	/* A masked text frame "Hello" (RFC 6455 section 5.7). */
	static const u_int8_t frame[] = {
		0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58
	};
	static const u_int8_t echo[] = { 0x81, 0x05, 'H', 'e', 'l', 'l', 'o' };
	size_t	n;
	char	*body;

	n = kh_exchange((const u_int8_t *)upgrade, sizeof(upgrade) - 1, frame,
	    sizeof(frame), resp, sizeof(resp));
	result("websocket-handshake",
	    strstr(resp, "HTTP/1.1 101") != NULL &&
	    strstr(resp, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != NULL, resp);
	body = strstr(resp, "\r\n\r\n");
	result("websocket-echo", body != NULL &&
	    (size_t)(body + 4 - resp) + sizeof(echo) <= n &&
	    memcmp(body + 4, echo, sizeof(echo)) == 0, resp);
}

static void
json_cases(void)
{
	static const char	 doc[] =
	    "{\"a\":{\"b\":[1,\"two\",true,null]},\"n\":-12.5,\"s\":\"x\\ty\"}";
	struct kore_json	 json;
	struct kore_json_item	*item;
	struct kore_buf		 buf;
	char			 out[256];

	kore_json_init(&json, doc, strlen(doc));
	result("json-parse", kore_json_parse(&json), kore_json_strerror());
	item = kore_json_find_array(json.root, "a/b");
	result("json-find-array", item != NULL, NULL);
	item = kore_json_find_string(json.root, "a/b[1]");
	result("json-find-index", item != NULL &&
	    !strcmp(item->data.string, "two"), NULL);
	item = kore_json_find_string(json.root, "s");
	result("json-string-escape", item != NULL &&
	    !strcmp(item->data.string, "x\ty"), NULL);
	item = kore_json_find_number(json.root, "n");
	result("json-number", item != NULL && item->data.number == -12.5, NULL);
	result("json-missing", kore_json_find_string(json.root, "a/c") == NULL,
	    NULL);

	kore_buf_init(&buf, 128);
	kore_json_item_tobuf(json.root, &buf);
	snprintf(out, sizeof(out), "%.*s", (int)buf.offset, (char *)buf.data);
	result("json-serialize", strstr(out, "\"b\":[1,\"two\",true,null]") != NULL &&
	    strstr(out, "\"n\":-12.5") != NULL, out);
	kore_buf_cleanup(&buf);
	kore_json_cleanup(&json);

	kore_json_init(&json, "{\"a\":", 5);
	result("json-reject-truncated", !kore_json_parse(&json), NULL);
	kore_json_cleanup(&json);
	kore_json_init(&json, "[1,2,]", 6);
	result("json-reject-trailing-comma", !kore_json_parse(&json), NULL);
	kore_json_cleanup(&json);
}

static void
util_cases(void)
{
	u_int8_t	*out;
	size_t		 olen;
	char		 s[64];
	int		 err;

	out = NULL;
	result("base64-decode", kore_base64_decode("aGVsbG8gd29ybGQ=", &out, &olen) &&
	    olen == 11 && !memcmp(out, "hello world", 11), NULL);
	kore_free(out);
	out = NULL;
	result("base64url-decode", kore_base64url_decode("_-8", &out, &olen,
	    KORE_BASE64_RAW) && olen == 2 && out[0] == 0xff && out[1] == 0xef, NULL);
	kore_free(out);
	result("date-to-time",
	    kore_date_to_time("Sun, 06 Nov 1994 08:49:37 GMT") == 784111777, NULL);
	snprintf(s, sizeof(s), "a%%20b+c%%41");
	result("urldecode", http_argument_urldecode(s, 1) == KORE_RESULT_OK &&
	    !strcmp(s, "a b cA"), s);
	result("strtonum64", kore_strtonum64("-42", 1, &err) == (u_int64_t)-42 &&
	    err == KORE_RESULT_OK, NULL);
	(void)kore_strtonum64("12x", 1, &err);
	result("strtonum64-reject", err == KORE_RESULT_ERROR, NULL);
}

int
main(void)
{
	init();

	http_case("get-root", "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
	    "HTTP/1.1 200", "server: kore", NULL);
	http_case("query-string",
	    "GET /api/x?id=abc123&n=-42&port=8080 HTTP/1.1\r\nHost: x\r\n\r\n",
	    "HTTP/1.1 200", "id=abc123\n", "n=-42\n", "port=8080\n", NULL);
	http_case_not("validator-rejects",
	    "GET /api/x?id=ABC!&n=1 HTTP/1.1\r\nHost: x\r\n\r\n",
	    "n=1\n", "id=");
	http_case("cookie",
	    "GET / HTTP/1.1\r\nHost: x\r\nCookie: a=1; sid=s3ss10n\r\n\r\n",
	    "HTTP/1.1 200", "sid=s3ss10n\n", NULL);
	http_case("post-urlencoded",
	    "POST /api/p HTTP/1.1\r\nHost: x\r\n"
	    "Content-Type: application/x-www-form-urlencoded\r\n"
	    "Content-Length: 16\r\n\r\nid=hello&name=wo",
	    "HTTP/1.1 200", "id=hello\n", NULL);
	http_case("post-multipart",
	    "POST /api/up HTTP/1.1\r\nHost: x\r\n"
	    "Content-Type: multipart/form-data; boundary=XyZ\r\n"
	    "Content-Length: 88\r\n\r\n"
	    "--XyZ\r\n"
	    "Content-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n"
	    "\r\nhello\r\n--XyZ--\r\n",
	    "HTTP/1.1 200", "file=a.txt:5\n", NULL);
	http_case("body-longer-than-content-length",
	    "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nabcdef",
	    "HTTP/1.1 413", NULL);
	http_case("auth-cookie-denied",
	    "GET /private HTTP/1.1\r\nHost: x\r\n\r\n",
	    "HTTP/1.1 302", "location: /login", NULL);
	http_case("auth-cookie-ok",
	    "GET /private HTTP/1.1\r\nHost: x\r\nCookie: session=letmein\r\n\r\n",
	    "HTTP/1.1 200", "private", NULL);
	http_case("auth-header-denied",
	    "GET /token HTTP/1.1\r\nHost: x\r\nX-Token: nope\r\n\r\n",
	    "HTTP/1.1 403", NULL);
	http_case("redirect",
	    "GET /old/thing HTTP/1.1\r\nHost: x\r\n\r\n",
	    "HTTP/1.1 301", "location: /new/thing", NULL);
	http_case("return-410", "GET /gone HTTP/1.1\r\nHost: x\r\n\r\n",
	    "HTTP/1.1 410", NULL);
	http_case("not-found", "GET /nope HTTP/1.1\r\nHost: x\r\n\r\n",
	    "HTTP/1.1 404", NULL);
	http_case("bad-method", "BREW / HTTP/1.1\r\nHost: x\r\n\r\n",
	    "HTTP/1.1 400", NULL);
	http_case("filemap-file", "GET /files/a.txt HTTP/1.1\r\nHost: x\r\n\r\n",
	    "HTTP/1.1 200", "hello from a.txt", NULL);
	http_case("filemap-index", "GET /static/ HTTP/1.1\r\nHost: x\r\n\r\n",
	    "HTTP/1.1 200", "<html>sub</html>", NULL);
	http_case("filemap-ext", "GET /files/page HTTP/1.1\r\nHost: x\r\n\r\n",
	    "HTTP/1.1 200", "<p>page</p>", NULL);
	http_case("filemap-traversal",
	    "GET /files/../../etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n",
	    "HTTP/1.1 404", NULL);
	websocket_case();
	json_cases();
	util_cases();

	printf("SUMMARY passed=%d failed=%d\n", passed, failed);
	return (failed == 0 ? 0 : 1);
}
