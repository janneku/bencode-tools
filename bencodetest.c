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

static void strtest(const char *s, size_t len, const char *expected, int success)
{
	struct bencode *b;
	b = ben_decode(s, len);
	if (success && b == NULL) {
		fprintf(stderr, "%s/%zd should have succeeded\n", s, len);
		exit(1);
	}
	if (success && strcmp(b->s.s, expected) != 0) {
		fprintf(stderr, "%s/%zd should have value %s\n", s, len, expected);
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

	strtest("0:", 2, "", 1);
	strtest("7:marklar", 9, "marklar", 1);
	strtest("7:marklar", 8, "marklar", 0);

	return 0;
}
