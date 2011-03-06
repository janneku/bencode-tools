#include <typevalidator/bencode.h>

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static void inttest(const char *s, size_t len, long long expected, int success)
{
	struct bencode *b;
	b = ben_decode(s, len);
	if (success && b == NULL) {
		fprintf(stderr, "%s/%zd should have succeeded\n", s, len);
		exit(1);
	}
	if (success && b->ll != expected) {
		fprintf(stderr, "%s/%zd should have value %lld\n", s, len, expected);
		exit(1);
	}
	if (!success && b != NULL) {
		fprintf(stderr, "%s/%zd should have failed\n", s, len);
		exit(1);
	}
	ben_free(b);
}

int main(void)
{
	inttest("i-1e", 4, -1, 1);
	inttest("i-1e", 3, -1, 0);
	inttest("i0e", 3, 0, 1);
	inttest("i1e", 3, 1, 1);
	inttest("ie", 2, 0, 0);
	inttest("i1ke", 4, 1, 0);
	return 0;
}
