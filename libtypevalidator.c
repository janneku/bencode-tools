#include <typevalidator/bencode.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

static struct bencode *decode(const char *data, size_t len, size_t *off, int l);

static size_t find(const char *data, size_t len, size_t off, char c)
{
	for (; off < len; off++) {
		if (data[off] == c)
			return off;
	}
	return -1;
}

static struct bencode *alloc(enum bencodetype type)
{
	struct bencode *b = calloc(1, sizeof *b);
	if (b == NULL)
		return NULL;
	b->type = type;
	return b;
}

static struct bencode *invalid(const char *reason, size_t off)
{
	fprintf(stderr, "bencode: %s: invalid data at position %zu\n", reason, off);
	return NULL;
}

static struct bencode *decode_bool(const char *data, size_t len, size_t *off)
{
	struct bencode *b;
	int value;
	char c;
	if ((*off + 2) > len)
		return invalid("Too short a data for bool", *off);
	c = data[*off + 1];
	if (c != '0' && c != '1')
		return invalid("Invalid bool value", *off);
	value = (c == '1');
	b = alloc(BENCODE_BOOL);
	if (b == NULL) {
		fprintf(stderr, "bencode: No memory for bool\n");
		return NULL;
	}
	b->b = value;
	*off += 2;
	return b;
}

static struct bencode *decode_dict(const char *data, size_t len, size_t *off)
{
	assert(0);
}

/* off is the position of first number in */
static int read_long_long(long long *ll, const char *data, size_t len,
			  size_t *off, int c)
{
	char buf[21]; /* fits all 64 bit integers */
	size_t pos;
	char *endptr;
	size_t slen;

	pos = find(data, len, *off, c);
	if (pos == -1)
		return -1;
	slen = pos - *off;
	if (slen == 0 || slen >= sizeof buf)
		return -1;
	assert(slen < sizeof buf);
	memcpy(buf, data + *off, slen);
	buf[slen] = 0;

	errno = 0;
	*ll = strtoll(buf, &endptr, 10);
	if (errno == ERANGE || *endptr != 0)
		return -1;

	*off = pos + 1;

	return 0;
}

static struct bencode *decode_int(const char *data, size_t len, size_t *off)
{
	struct bencode *b;
	long long ll;
	size_t newoff = *off + 1;
	if (read_long_long(&ll, data, len, &newoff, 'e'))
		return invalid("bad integer value", *off);
	b = alloc(BENCODE_INT);
	if (b == NULL) {
		fprintf(stderr, "bencode: No memory for int\n");
		return NULL;
	}
	b->ll = ll;
	*off = newoff;
	return b;
}

static int resize_list(struct bencode_list *list)
{
	struct bencode **newvalues;
	size_t newsize;
	size_t maxalloc = ((size_t) -1) / sizeof(list->values[0]) / 2;

	if (list->alloc >= maxalloc)
		return -1;
	list->alloc *= 2;
	newsize = sizeof(list->values[0]) * list->alloc;
	newvalues = realloc(list->values, newsize);
	if (newvalues == NULL)
		return -1;
	list->values = newvalues;
	return 0;
}

static struct bencode *decode_list(const char *data, size_t len, size_t *off, int level)
{
	struct bencode *l;
	size_t oldoff = *off;

	l = alloc(BENCODE_LIST);
	if (l == NULL) {
		fprintf(stderr, "bencode: No memory for list\n");
		return NULL;
	}

	l->l.alloc = 4;
	l->l.values = malloc(sizeof(l->l.values[0]) * l->l.alloc);
	if (l->l.values == NULL) {
		fprintf(stderr, "bencode: No memory for list values\n");
		goto error;
	}

	*off += 1;

	while (*off < len && data[*off] != 'e') {
		struct bencode *b;
		if (l->l.n == l->l.alloc && resize_list(&l->l)) {
			fprintf(stderr, "bencode: Can not resize list: %zu\n", oldoff);
			goto error;
		}
		b = decode(data, len, off, level);
		if (b == NULL)
			goto error;
		l->l.values[l->l.n] = b;
		l->l.n += 1;
	}

	if (*off >= len) {
		fprintf(stderr, "bencode: List not terminated: %zu\n", oldoff);
		goto error;
	}

	*off += 1;

	return l;

error:
	ben_free(l);
	return NULL;
}

static size_t read_size_t(const char *data, size_t len, size_t *off, int c)
{
	long long ll;
	size_t s;
	size_t newoff = *off;
	if (read_long_long(&ll, data, len, &newoff, c))
		return -1;
	if (ll < 0)
		return -1;
	/*
	 * Test that information is not lost when converting from long long
	 * to size_t
	 */
	s = (size_t) ll;
	if (ll != (long long) s)
		return -1;

	*off = newoff;
	return s;
}

static struct bencode *decode_str(const char *data, size_t len, size_t *off)
{
	size_t datalen;
	struct bencode *b;
	size_t newoff = *off;

	/* Read the string length */
	datalen = read_size_t(data, len, &newoff, ':');
	if (datalen == -1)
		return invalid("invalid string length", *off);

	if ((newoff + datalen) > len)
		return invalid("string out of bounds", *off);

	/* Allocate string structure and copy data into it */
	b = alloc(BENCODE_STR);
	if (b == NULL) {
		fprintf(stderr, "bencode: No memory for str structure\n");
		return NULL;
	}	
	b->s.s = malloc(datalen);
	if (b->s.s == NULL) {
		free(b);
		fprintf(stderr, "bencode: No memory for string\n");
		return NULL;
	}
	memcpy(b->s.s, data + newoff, datalen);
	b->s.len = datalen;

	*off = newoff + datalen;
	return b;
}

static struct bencode *decode(const char *data, size_t len, size_t *off, int l)
{
	l++;
	if (l > 256)
		return NULL;
	if (*off == len)
		return NULL;
	assert (*off < len);
	switch (data[*off]) {
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
		return decode_str(data, len, off);
	case 'b':
		return decode_bool(data, len, off);
	case 'd':
		return decode_dict(data, len, off);
	case 'i':
		return decode_int(data, len, off);
	case 'l':
		return decode_list(data, len, off, l);
	default:
		return invalid("unknown bencode type", *off);
	}
}

struct bencode *ben_decode(const void *data, size_t len)
{
	size_t off = 0;
	return decode((const char *) data, len, &off, 0);
}

struct bencode *ben_decode2(const void *data, size_t len, size_t *off)
{
	return decode((const char *) data, len, off, 0);
}

static void free_dict(struct bencode_dict *dict)
{
	dict = dict;
	assert(0);
}

static void free_list(struct bencode_list *list)
{
	size_t pos;
	for (pos = 0; pos < list->n; pos++) {
		ben_free(list->values[pos]);
		list->values[pos] = NULL;
	}
}

void ben_free(struct bencode *b)
{
	if (b == NULL)
		return;
	switch (b->type) {
	case BENCODE_BOOL:
		break;
	case BENCODE_DICT:
		free_dict(&b->d);
		break;
	case BENCODE_INT:
		break;
	case BENCODE_LIST:
		free_list(&b->l);
		break;
	case BENCODE_STR:
		free(b->s.s);
		break;
	default:
		fprintf(stderr, "bencode: invalid type: %d\n", b->type);
		exit(1);
	}
	memset(b, -1, sizeof *b); /* data poison */
	free(b);
}
