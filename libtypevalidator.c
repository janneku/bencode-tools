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

static struct bencode *overflow(size_t off)
{
	fprintf(stderr, "bencode: overflow at position %zu\n", off);
	return NULL;
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
	if ((*off + 2) > len)
		return invalid("Too short a data for bool", *off);

	switch (data[*off + 1]) {
	case '0':
		value = 0;
		break;
	case '1':
		value = 1;
		break;
	default:
		return invalid("Invalid bool value", *off);
	}

	b = alloc(BENCODE_BOOL);
	if (b == NULL) {
		fprintf(stderr, "bencode: No memory for bool\n");
		return NULL;
	}
	b->b = value;
	*off += 2;
	return b;
}

static struct bencode *decode_int(const char *data, size_t len, size_t *off)
{
	/* fits all 64 bit integers */
	char buf[21];
	size_t slen;
	struct bencode *b;
	char *endptr;
	size_t pos;
	long long ll;

	pos = find(data, len, *off + 1, 'e');
	if (pos == -1)
		return overflow(*off);
	slen = pos - *off - 1;
	if (slen == 0 || slen >= sizeof buf)
		return invalid("bad int slen", *off);
	assert(slen < sizeof buf);
	memcpy(buf, data + *off + 1, slen);
	buf[slen] = 0;
	errno = 0;
	ll = strtoll(buf, &endptr, 10);
	if (errno == ERANGE || *endptr != 0)
		return invalid("bad int string", *off);
	b = alloc(BENCODE_INT);
	if (b == NULL) {
		fprintf(stderr, "bencode: No memory for int\n");
		return NULL;
	}
	b->ll = ll;
	*off = pos + 1;
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

static size_t read_size_t(const char *buf)
{
	char *endptr;
	long long ll;
	size_t s;

	errno = 0;
	/* Note: value equal to ((size_t) -1) is not valid */
	ll = strtoll(buf, &endptr, 10);
	if (errno == ERANGE || *endptr != 0)
		return -1;
	if (ll < 0)
		return -1;
	s = (size_t) ll;
	if (ll != (long long) s)
		return -1;
	return s;
}

static struct bencode *decode_str(const char *data, size_t len, size_t *off)
{
	char buf[21];
	size_t pos;
	size_t slen;
	size_t datalen;
	struct bencode *b;
	size_t newoff;

	pos = find(data, len, *off + 1, ':');
	if (pos == -1)
		return overflow(*off);
	slen = pos - *off;
	if (slen == 0 || slen >= sizeof buf)
		return invalid("no string length", *off);
	assert(slen < sizeof buf);
	memcpy(buf, data + *off, slen);
	buf[slen] = 0;

	/* Read the string length */
	datalen = read_size_t(buf);
	if (datalen == -1)
		return invalid("invalid string length", *off);

	newoff = pos + 1 + datalen;
	if (newoff > len)
		return invalid("too long a string (data out of bounds)", *off);

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
	memcpy(b->s.s, data + pos + 1, datalen);
	b->s.len = datalen;

	*off = newoff;
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
