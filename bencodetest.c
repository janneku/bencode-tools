#include <bencodetools/bencode.h>

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static void booltest(const char *s, size_t len, int expected, int experror)
{
	struct bencode_bool *b;
	size_t off = 0;
	int error;
	b = (struct bencode_bool *) ben_decode2(s, len, &off, &error);
	if (experror != error) {
		fprintf(stderr, "%s/%zd should got code %d but got %d\n", s, len, experror, error);
		exit(1);
	}
	if (experror == BEN_OK && b == NULL) {
		fprintf(stderr, "%s/%zd should have succeeded\n", s, len);
		exit(1);
	}
	if (experror == BEN_OK && b->b != expected) {
		fprintf(stderr, "%s/%zd should have value %d\n", s, len, expected);
		exit(1);
	}
	if (experror != BEN_OK && b != NULL) {
		fprintf(stderr, "%s/%zd should have failed\n", s, len);
		exit(1);
	}
	ben_free((struct bencode *) b);
}

static void inttest(const char *s, size_t len, long long expected, int experror)
{
	struct bencode_int *b;
	size_t off = 0;
	int error;
	b = (struct bencode_int *) ben_decode2(s, len, &off, &error);
	if (error != experror) {
		fprintf(stderr, "%s/%zd should get code %d but got %d\n", s, len, experror, error);
		exit(1);
	}
	if (experror == BEN_OK && b == NULL) {
		fprintf(stderr, "%s/%zd should have succeeded\n", s, len);
		exit(1);
	}
	if (experror == BEN_OK && b->ll != expected) {
		fprintf(stderr, "%s/%zd should have value %lld\n", s, len, expected);
		exit(1);
	}
	if (experror != BEN_OK && b != NULL) {
		fprintf(stderr, "%s/%zd should have failed\n", s, len);
		exit(1);
	}
	ben_free((struct bencode *) b);
}

static void strtest(const char *s, size_t len, const char *expected, int experror)
{
	struct bencode_str *b;
	size_t off = 0;
	int error;
	b = (struct bencode_str *) ben_decode2(s, len, &off, &error);
	if (error != experror) {
		fprintf(stderr, "%s/%zd should get code %d but got %d\n", s, len, experror, error);
		exit(1);
	}
	if (experror == BEN_OK && b == NULL) {
		fprintf(stderr, "%s/%zd should have succeeded\n", s, len);
		exit(1);
	}
	if (experror == BEN_OK && memcmp(b->s, expected, strlen(expected)) != 0) {
		fprintf(stderr, "%s/%zd should have value %s\n", s, len, expected);
		exit(1);
	}
	if (experror != BEN_OK && b != NULL) {
		fprintf(stderr, "%s/%zd should have failed\n", s, len);
		exit(1);
	}
	ben_free((struct bencode *) b);
}

static void listtest(const char *s, size_t len, size_t expected, int experror)
{
	struct bencode_list *b;
	size_t off = 0;
	int error;
	b = (struct bencode_list *) ben_decode2(s, len, &off, &error);
	if (error != experror) {
		fprintf(stderr, "%s/%zd should get code %d but got %d\n", s, len, experror, error);
		exit(1);
	}
	if (experror == BEN_OK && b == NULL) {
		fprintf(stderr, "%s/%zd should have succeeded\n", s, len);
		exit(1);
	}
	if (experror == BEN_OK && b->n != expected) {
		fprintf(stderr, "%s/%zd should have %zu entries\n", s, len, expected);
		exit(1);
	}
	if (experror != BEN_OK && b != NULL) {
		fprintf(stderr, "%s/%zd should have failed\n", s, len);
		exit(1);
	}
	ben_free((struct bencode *) b);
}

static void dicttest(const char *s, size_t len, size_t expected, int experror)
{
	struct bencode_dict *b;
	size_t off = 0;
	int error;
	b = (struct bencode_dict *) ben_decode2(s, len, &off, &error);
	if (error != experror) {
		fprintf(stderr, "%s/%zd should get code %d but got %d\n", s, len, experror, error);
		exit(1);
	}
	if (experror == BEN_OK && b == NULL) {
		fprintf(stderr, "%s/%zd should have succeeded\n", s, len);
		exit(1);
	}
	if (experror == BEN_OK && b->n != expected) {
		fprintf(stderr, "%s/%zd should have %zu entries\n", s, len, expected);
		exit(1);
	}
	if (experror != BEN_OK && b != NULL) {
		fprintf(stderr, "%s/%zd should have failed\n", s, len);
		exit(1);
	}
	ben_free((struct bencode *) b);
}

static void print_tests(void)
{	
	struct test {
		char *encoded;
		size_t len;
		char *expected;
	};
	const struct test table[] = {
		{"d3:foo3:bare", -1, "{'foo': 'bar'}"},
		{"di0e0:i1e0:e", -1, "{0: '', 1: ''}"},
		{"di0eli1eei1e0:e", -1, "{0: [1], 1: ''}"},
		{"di0eli1ei2eei1e0:e", -1, "{0: [1, 2], 1: ''}"},
		{"1:\x00", 3, "'\\x00'"},
		{"1:\x01", 3, "'\\x01'"},
		{"1:\a", 3, "'\\x07'"},
		{"1:\b", 3, "'\\x08'"},
		{"1:\t", 3, "'\\x09'"},
		{"1:\n", 3, "'\\x0a'"},
		{"1:\r", 3, "'\\x0d'"},
		{"1: ", 3, "' '"},
		{"1:0", 3, "'0'"},
		{"1:A", 3, "'A'"},
		{"1:a", 3, "'a'"},
		{"1:\\", 3, "'\\\\'"},
		{"1:'", 3, "'\\''"},
		{"1:\x7f", 3, "'\\x7f'"},
		{"1:\xff", 3, "'\\xff'"},
		{"b0", -1, "False"},
		{"b1", -1, "True"},
		{"i0e", -1, "0"},
		{"i-1e", -1, "-1"},
		{"0:", -1, "''"},
		{"3:foo", -1, "'foo'"},
		{"le", -1, "[]"},
		{"li0ee", -1, "[0]"},
		{"li0ei1ee", -1, "[0, 1]"},
		{NULL, 0, NULL}};

	size_t i;
	char *printed;
	struct bencode *b;

	for (i = 0; table[i].encoded != NULL; i++) {
		const char *encoded = table[i].encoded;
		size_t len = table[i].len;
		const char *expected = table[i].expected;
		if (len == -1)
			len = strlen(encoded);
		b = ben_decode(encoded, len);
		if (b == NULL) {
			fprintf(stderr, "Failed to decode: %s\n", encoded);
			exit(1);
		}
		printed = ben_print(b);
		if (printed == NULL) {
			fprintf(stderr, "Failed to print: %s\n", expected);
			exit(1);
		}
		if (strcmp(printed, expected) != 0) {
			fprintf(stderr, "Invalid print output: %s vs %s\n", printed, expected);
			exit(1);
		}
		ben_free(b);
		free(printed);
	}
}

static void encoded_size_tests(void)
{
	struct bencode *key;
	struct bencode *value;
	struct bencode *b;
	struct bencode *d;
	struct bencode *l;
	char data[4096];
	size_t s;
	size_t pos;

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
	s = 0;
	ben_list_for_each(b, pos, l)
		s += ben_encoded_size(b);
	assert(s == 12);
	ben_free(l);
	l = NULL;

	d = ben_dict();
	assert(ben_encoded_size(d) == 2);
	ben_dict_set(d, ben_int(1), ben_str(""));
	ben_dict_set(d, ben_int(0), ben_str(""));
	ben_dict_set(d, ben_int(0), ben_str(""));
	s = ben_encode2(data, sizeof data, d);
	assert(s == 12);
	assert(memcmp(data, "di0e0:i1e0:e", s) == 0);
	s = 0;
	ben_dict_for_each(key, value, pos, d) {
		s += ben_encoded_size(key);
		s += ben_encoded_size(value);
	}
	assert(s == 10);
	ben_free(d);
}

static void testvectors(const char **vec, int success)
{
	while (*vec != NULL) {
		struct bencode * b = ben_decode(*vec, strlen(*vec));
		if (success && b == NULL) {
			fprintf(stderr, "test vector %s failed. it should be valid.)\n", *vec);
			exit(1);
		}
		if (!success && b != NULL) {
			fprintf(stderr, "test vector %s failed. it should be invalid.\n", *vec);
			exit(1);
		}
		ben_free(b);
		vec++;
	}
}

static void misc_tests(void)
{
	const char *validvectors[] = {
		"i4e",
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
		"l0:0:0:e",
		"l3:asd2:xye",
		"di1e0:e",
		NULL
	       };
	const char *invalidvectors[] = {
		"0:0:",
		"ie",
		"i341foo382e",
		"i 0e",
		"i-0e",
		"i123",
		"",
		"i6easd",
		"35208734823ljdahflajhdf",
		"2:abfdjslhfld",
		"02:xy",
		"d",
		"i",
		"l",
		"0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
		"leanfdldjfh",
		"relwjhrlewjh",
		"defoobar",
		"d3:fooe",
		"d1:b0:1:a0:e", /* demand order for keys */
		"di1e0:i0e0:e", /* demand order for keys */
		"d1:a0:1:a0:e", /* disallow same two keys */
		"di0e0:i0e0:e", /* disallow same two keys */
		NULL
	       };
	testvectors(validvectors, 1);
	testvectors(invalidvectors, 0);
}

static void dict_tests(void)
{
	struct bencode *d = ben_dict();
	struct bencode *i = ben_int(0);
	struct bencode *key2 = ben_str("key2");
	struct bencode *i2 = ben_int(0);

	assert(d != NULL && i != NULL && key2 != NULL && i2 != NULL);
	assert(ben_dict_set_by_str(d, "key", i) == 0);
	assert(ben_dict_get_by_str(d, "key") != NULL);
	assert(ben_dict_set(d, key2, i2) == 0);
	assert(ben_dict_get(d, key2) != NULL);
}

int main(void)
{
	assert(ben_decode("i0e ", 4) == NULL);

	booltest("b0", 1, 0, BEN_INSUFFICIENT);
	booltest("b0", 2, 0, BEN_OK);
	booltest("b0 ", 3, 0, BEN_OK);
	booltest("b1", 2, 1, BEN_OK);
	booltest("b2", 2, 1, BEN_INVALID);

	inttest("i-1e", 4, -1, BEN_OK);
	inttest("i-1e", 3, -1, BEN_INSUFFICIENT);
	inttest("i0e", 3, 0, BEN_OK);
	inttest("i1e", 3, 1, BEN_OK);
	inttest("ie", 2, 0, BEN_INVALID);
	inttest("i1ke", 4, 1, BEN_INVALID);
	inttest("i123456789e", 11, 123456789, BEN_OK);

	strtest("0", 1, "", BEN_INSUFFICIENT);
	strtest("0:", 1, "", BEN_INSUFFICIENT);
	strtest("0:", 2, "", BEN_OK);
	strtest("0e", 2, "", BEN_INSUFFICIENT);
	strtest("0e:", 3, "", BEN_INVALID);
	strtest("7:marklar", 9, "marklar", BEN_OK);
	strtest("7:marklar", 8, "marklar", BEN_INSUFFICIENT);

	listtest("le", 2, 0, BEN_OK);
	listtest("lfe", 3, 0, BEN_INVALID);
	listtest("li0ee", 5, 1, BEN_OK);
	listtest("li0e", 4, 1, BEN_INSUFFICIENT);
	listtest("li0ei", 5, 1, BEN_INSUFFICIENT);
	listtest("li0ei1", 6, 1, BEN_INSUFFICIENT);
	listtest("li0ei1e", 7, 1, BEN_INSUFFICIENT);
	listtest("li0ei", 5, 1, BEN_INSUFFICIENT);
	listtest("li0ef", 5, 1, BEN_INVALID);
	listtest("li0ei0ee", 8, 2, BEN_OK);
	listtest("li0ei0ei0ee", 11, 3, BEN_OK);
	listtest("li0ei0ei0ei0ee", 14, 4, BEN_OK);
	listtest("li0ei0ei0ei0ei0ee", 17, 5, BEN_OK);
	listtest("l7:marklare", 11, 1, BEN_OK);
	listtest("l7:marklari0ee", 14, 2, BEN_OK);
	listtest("l7:marklarf", 11, 1, BEN_INVALID);

	dicttest("d", 1, 1, BEN_INSUFFICIENT);
	dicttest("di0e7:marklare", 14, 1, BEN_OK);
	dicttest("di0e", 4, 1, BEN_INSUFFICIENT);
	dicttest("di0e7", 5, 1, BEN_INSUFFICIENT);
	dicttest("di0e7:", 6, 1, BEN_INSUFFICIENT);
	dicttest("di0e7:marklar", 13, 1, BEN_INSUFFICIENT);
	dicttest("di0e7:marklare", 13, 1, BEN_INSUFFICIENT);
	dicttest("di0e7:marklari1e7:marklare", 26, 2, BEN_OK);
	dicttest("de", 2, 0, BEN_OK);

	encoded_size_tests();

	misc_tests();

	print_tests();

	dict_tests();

	return 0;
}
