/*
 * kore configuration-file harness (Mayhem integration, AFL file-input target):
 *     fuzz_config <kore.conf>
 * parses the file with kore_parse_config_file(), the parser behind `kore -c`.
 *
 * kore's config parser reports every invalid line with fatal(), which exit()s, so this
 * is a one-input-per-process file target rather than a libFuzzer harness.
 *
 * Directives whose documented effect (conf/kore.conf.example) is to act on the host
 * rather than to configure the parser's own state are rejected before parsing: they
 * open or unlink files and sockets, load shared objects or chroot/setuid
 * (bind, unix, load, include, accesslog, logfile, pidfile, rand_file, certfile,
 * certkey, tls_dhparam, root, runas, http_body_disk_path, python_*, file). The match
 * reproduces the parser's own tokenisation (kore_read_line(): leading whitespace
 * skipped, tabs turned into spaces; the directive is the text up to the first space,
 * trimmed by kore_text_trim()), so a rejected directive cannot reach its handler.
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "kore.h"
#include "http.h"

/*
 * Handlers and validators named by the seed configurations (conf/kore.conf.example and
 * mayhem/config/testsuite), resolved with dlsym() on this binary (-rdynamic) when a
 * route or validator is configured, so parsing gets past those lines.
 */
int	page(struct http_request *);
int	index_page(struct http_request *);
int	login_do(struct http_request *);
int	myhandler(struct http_request *);
int	mypages_index(struct http_request *);
int	v_func(struct http_request *, const void *);
int	v_example_func(struct http_request *, const void *);
int	v_session_validate(struct http_request *, const void *);

int page(struct http_request *req) { (void)req; return (KORE_RESULT_OK); }
int index_page(struct http_request *req) { (void)req; return (KORE_RESULT_OK); }
int login_do(struct http_request *req) { (void)req; return (KORE_RESULT_OK); }
int myhandler(struct http_request *req) { (void)req; return (KORE_RESULT_OK); }
int mypages_index(struct http_request *req) { (void)req; return (KORE_RESULT_OK); }
int v_func(struct http_request *req, const void *d) { (void)req; (void)d; return (KORE_RESULT_OK); }
int v_example_func(struct http_request *req, const void *d) { (void)req; (void)d; return (KORE_RESULT_OK); }
int v_session_validate(struct http_request *req, const void *d) { (void)req; (void)d; return (KORE_RESULT_OK); }

static const char *denied[] = {
	"bind", "unix", "load", "include", "accesslog", "logfile", "pidfile",
	"rand_file", "certfile", "certkey", "tls_dhparam", "root", "runas",
	"http_body_disk_path", "python_path", "python_import", "file", NULL
};

static int
line_denied(char *line)
{
	char	*p, *t;
	int	 i;

	p = line;
	while (isspace(*(unsigned char *)p))
		p++;
	for (t = p; *t != '\0'; t++) {
		if (*t == '\t')
			*t = ' ';
	}
	if ((t = strchr(p, ' ')) == NULL)
		return (0);
	*t = '\0';
	p = kore_text_trim(p, strlen(p));
	for (i = 0; denied[i] != NULL; i++) {
		if (!strcmp(p, denied[i]))
			return (1);
	}
	return (0);
}

int
main(int argc, char *argv[])
{
	FILE	*fp;
	char	 buf[BUFSIZ];

	if (argc != 2) {
		fprintf(stderr, "usage: %s <kore.conf>\n", argv[0]);
		return (1);
	}

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
	kore_module_load(NULL, NULL, KORE_MODULE_NATIVE);

	if ((fp = fopen(argv[1], "r")) == NULL) {
		perror(argv[1]);
		return (1);
	}
	/* Same line reader and buffer size as kore_parse_config_file(). */
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		buf[strcspn(buf, "\n")] = '\0';
		if (line_denied(buf)) {
			fclose(fp);
			return (0);
		}
	}
	rewind(fp);

	kore_parse_config_file(fp);
	fclose(fp);
	return (0);
}
