/*
 * kore string-decoder harness (Mayhem integration): the decoders kore applies to
 * request data (Authorization/cookie base64, If-Modified-Since dates, url-encoded
 * arguments, numeric arguments, split header lists). The first byte selects the
 * decoder; the rest is the NUL-terminated string it is given.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kore.h"
#include "http.h"

int	LLVMFuzzerTestOneInput(const u_int8_t *, size_t);

int
LLVMFuzzerTestOneInput(const u_int8_t *data, size_t len)
{
	static int	 inited;
	char		*s, *argv[10];
	u_int8_t	*out;
	size_t		 olen;
	int		 err;

	if (len < 1)
		return (-1);
	if (!inited) {
		kore_quiet = 1;
		kore_mem_init();
		kore_msg_init();
		kore_log_init();
		inited = 1;
	}

	s = kore_malloc(len);
	memcpy(s, data + 1, len - 1);
	s[len - 1] = '\0';

	out = NULL;
	switch (data[0] % 8) {
	case 0:
		if (kore_base64_decode(s, &out, &olen))
			kore_free(out);
		break;
	case 1:
		if (kore_base64url_decode(s, &out, &olen, KORE_BASE64_RAW))
			kore_free(out);
		break;
	case 2:
		if (kore_base64url_decode(s, &out, &olen, 0))
			kore_free(out);
		break;
	case 3:
		(void)kore_date_to_time(s);
		break;
	case 4:
		(void)http_argument_urldecode(s, 0);
		break;
	case 5:
		(void)http_argument_urldecode(s, 1);
		break;
	case 6:
		(void)kore_strtonum64(s, 0, &err);
		(void)kore_strtonum64(s, 1, &err);
		(void)kore_strtonum(s, 10, -1000, 1000, &err);
		break;
	case 7:
		(void)kore_split_string(s, ",", argv, 10);
		break;
	}

	kore_free(s);
	return (0);
}
