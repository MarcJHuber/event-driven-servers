#include "misc/mypcre2.h"

static uint32_t jit_supported = 0;
static uint32_t once = 1;

pcre2_code *mypcre2_compile(PCRE2_SPTR pattern, PCRE2_SIZE length, uint32_t options, int *errorcode, PCRE2_SIZE *erroroffset, pcre2_compile_context *ccontext)
{
	if (once) {
		once = 0;
		pcre2_config(PCRE2_CONFIG_JIT, &jit_supported);
	}
	pcre2_code *res = pcre2_compile(pattern, length, options, errorcode, erroroffset, ccontext);
	if (res && jit_supported)
		pcre2_jit_compile(res, PCRE2_JIT_COMPLETE);
	return res;
}

int mypcre2_match(const pcre2_code *code, PCRE2_SPTR subject, PCRE2_SIZE length, PCRE2_SIZE startoffset, uint32_t options, pcre2_match_data *match_data, pcre2_match_context *mcontext)
{
	int res = pcre2_match(code, subject, length, startoffset, options, match_data, mcontext);
        if (res == PCRE2_ERROR_JIT_STACKLIMIT)
		options |= PCRE2_NO_JIT;
	return pcre2_match(code, subject, length, startoffset, options, match_data, mcontext);
}
