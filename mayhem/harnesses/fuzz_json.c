/*
 * kore JSON harness (Mayhem integration): the input is a JSON document as an
 * application would hand it to kore's JSON API from a request body
 * (kore_json_init + kore_json_parse), then looked up (kore_json_find) and
 * serialized back (kore_json_item_tobuf).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kore.h"

int	LLVMFuzzerTestOneInput(const u_int8_t *, size_t);

static const char *paths[] = {
	"a", "a/b", "a/b/c", "items[0]", "items[1]/name", "x[0][0]", "", NULL
};
static const u_int32_t types[] = {
	KORE_JSON_TYPE_OBJECT, KORE_JSON_TYPE_ARRAY, KORE_JSON_TYPE_STRING,
	KORE_JSON_TYPE_NUMBER, KORE_JSON_TYPE_LITERAL, KORE_JSON_TYPE_INTEGER,
	KORE_JSON_TYPE_INTEGER_U64
};

int
LLVMFuzzerTestOneInput(const u_int8_t *data, size_t len)
{
	static int		 inited;
	struct kore_json	 json;
	struct kore_buf		 buf;
	size_t			 i, t;

	if (!inited) {
		kore_quiet = 1;
		kore_mem_init();
		kore_msg_init();
		kore_log_init();
		inited = 1;
	}

	kore_json_init(&json, data, len);
	if (kore_json_parse(&json)) {
		for (i = 0; paths[i] != NULL; i++) {
			for (t = 0; t < sizeof(types) / sizeof(types[0]); t++)
				(void)kore_json_find(json.root, paths[i], types[t]);
		}
		kore_buf_init(&buf, 128);
		kore_json_item_tobuf(json.root, &buf);
		kore_buf_cleanup(&buf);
	} else {
		(void)kore_json_strerror();
	}
	kore_json_cleanup(&json);
	return (0);
}
