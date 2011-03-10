#include <typevalidator/bencode.h>

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static void booltest(const char *s, size_t len, int expected, int success)
{
	struct bencode_bool *b;
	b = (struct bencode_bool *) ben_decode(s, len);
	if (success && b == NULL) {
		fprintf(stderr, "%s/%zd should have succeeded\n", s, len);
		exit(1);
	}
	if (success && b->b != expected) {
		fprintf(stderr, "%s/%zd should have value %d\n", s, len, expected);
		exit(1);
	}
	if (!success && b != NULL) {
		fprintf(stderr, "%s/%zd should have failed\n", s, len);
		exit(1);
	}
	ben_free((struct bencode *) b);
}

static void inttest(const char *s, size_t len, long long expected, int success)
{
	struct bencode_int *b;
	b = (struct bencode_int *) ben_decode(s, len);
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
	ben_free((struct bencode *) b);
}

static void strtest(const char *s, size_t len, const char *expected, int success)
{
	struct bencode_str *b;
	b = (struct bencode_str *) ben_decode(s, len);
	if (success && b == NULL) {
		fprintf(stderr, "%s/%zd should have succeeded\n", s, len);
		exit(1);
	}
	if (success && memcmp(b->s, expected, strlen(expected)) != 0) {
		fprintf(stderr, "%s/%zd should have value %s\n", s, len, expected);
		exit(1);
	}
	if (!success && b != NULL) {
		fprintf(stderr, "%s/%zd should have failed\n", s, len);
		exit(1);
	}
	ben_free((struct bencode *) b);
}

static void listtest(const char *s, size_t len, size_t expected, int success)
{
	struct bencode_list *b;
	b = (struct bencode_list *) ben_decode(s, len);
	if (success && b == NULL) {
		fprintf(stderr, "%s/%zd should have succeeded\n", s, len);
		exit(1);
	}
	if (success && b->n != expected) {
		fprintf(stderr, "%s/%zd should have %zu entries\n", s, len, expected);
		exit(1);
	}
	if (!success && b != NULL) {
		fprintf(stderr, "%s/%zd should have failed\n", s, len);
		exit(1);
	}
	ben_free((struct bencode *) b);
}

static void dicttest(const char *s, size_t len, size_t expected, int success)
{
	struct bencode_dict *b;
	b = (struct bencode_dict *) ben_decode(s, len);
	if (success && b == NULL) {
		fprintf(stderr, "%s/%zd should have succeeded\n", s, len);
		exit(1);
	}
	if (success && b->n != expected) {
		fprintf(stderr, "%s/%zd should have %zu entries\n", s, len, expected);
		exit(1);
	}
	if (!success && b != NULL) {
		fprintf(stderr, "%s/%zd should have failed\n", s, len);
		exit(1);
	}
	ben_free((struct bencode *) b);
}

static void encoded_size_tests(void)
{
	struct bencode *d;
	struct bencode *l;

	assert(ben_encoded_size(ben_bool(0)) == 2);
	assert(ben_encoded_size(ben_bool(1)) == 2);

	assert(ben_encoded_size(ben_int(-10)) == 5);
	assert(ben_encoded_size(ben_int(-1)) == 4);
	assert(ben_encoded_size(ben_int(0)) == 3);
	assert(ben_encoded_size(ben_int(1)) == 3);
	assert(ben_encoded_size(ben_int(10)) == 4);

	assert(ben_encoded_size(ben_str("marklar")) == 9);

	l = ben_list();
	assert(ben_encoded_size(l) == 2);
	ben_list_append(l, ben_int(0));
	assert(ben_encoded_size(l) == 5);
	ben_list_append(l, ben_str("marklar"));
	assert(ben_encoded_size(l) == 14);

	d = ben_dict();
	assert(ben_encoded_size(d) == 2);
}

static void misctests(void)
{
	const char *bencodevectors[] = {"i4e",
					"i0e",
					"i-10e",
					"i9223372036854775807e",
					"i-9223372036854775808e",
					"0:",
					"3:abc",
					"10:1234567890",
					"le",
					"li1ei2ei3ee",
					"ll5:Alice3:Bobeli2ei3eee",
					"de",
					"d3:agei25e4:eyes4:bluee",
					"d8:spam.mp3d6:author5:Alice6:lengthi100000eee",
					"b0",
					"b1",
					"lb1i2ee",
					"li2eb0e",
					NULL
				       };
	const char **vec = bencodevectors;
	while (*vec != NULL) {
		struct bencode * b = ben_decode(*vec, strlen(*vec));
		if (b == NULL) {
			fprintf(stderr, "test vector %s failed\n", *vec);
			exit(1);
		}
		vec++;
	}
}

int main(void)
{
	booltest("b0", 1, 0, 0);
	booltest("b0", 2, 0, 1);
	booltest("b1", 2, 1, 1);
	booltest("b2", 2, 1, 0);

	inttest("i-1e", 4, -1, 1);
	inttest("i-1e", 3, -1, 0);
	inttest("i0e", 3, 0, 1);
	inttest("i1e", 3, 1, 1);
	inttest("ie", 2, 0, 0);
	inttest("i1ke", 4, 1, 0);

	strtest("0:", 2, "", 1);
	strtest("7:marklar", 9, "marklar", 1);
	strtest("7:marklar", 8, "marklar", 0);

	listtest("le", 2, 0, 1);
	listtest("li0ee", 5, 1, 1);
	listtest("li0ei0ee", 8, 2, 1);
	listtest("li0ei0ei0ee", 11, 3, 1);
	listtest("li0ei0ei0ei0ee", 14, 4, 1);
	listtest("li0ei0ei0ei0ei0ee", 17, 5, 1);
	listtest("l7:marklare", 11, 1, 1);
	listtest("l7:marklari0ee", 14, 2, 1);
	listtest("l7:marklarf", 11, 1, 0);

	dicttest("di0e7:marklare", 14, 1, 1);
	dicttest("di0e7:marklare", 13, 1, 0);
	dicttest("di0e7:marklari0e7:marklare", 26, 2, 1);
	dicttest("de", 2, 0, 1);

	encoded_size_tests();

	misctests();

	return 0;
}
