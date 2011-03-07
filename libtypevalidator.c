#include <typevalidator/bencode.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

static struct bencode *decode(const char *data, size_t len, size_t *off,
			      int level);

static size_t find(const char *data, size_t len, size_t off, char c)
{
	for (; off < len; off++) {
		if (data[off] == c)
			return off;
	}
	return -1;
}

static size_t type_size(int type)
{
	switch (type) {
	case BENCODE_BOOL:
		return sizeof(struct bencode_bool);
	case BENCODE_DICT:
		return sizeof(struct bencode_dict);
	case BENCODE_INT:
		return sizeof(struct bencode_int);
	case BENCODE_LIST:
		return sizeof(struct bencode_list);
	case BENCODE_STR:
		return sizeof(struct bencode_str);
	default:
		fprintf(stderr, "Unknown bencode type: %d\n", type);
		exit(1);
	}
	return 0;
}

static void *alloc(int type)
{
	struct bencode *b = calloc(1, type_size(type));
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
	struct bencode_bool *b;
	char value;
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
	return (struct bencode *) b;
}

static int resize_dict(struct bencode_dict *d)
{
	struct bencode **newkeys;
	struct bencode **newvalues;
	size_t newsize;
	size_t maxalloc = ((size_t) -1) / sizeof(d->keys[0]) / 2;

	if (d->alloc >= maxalloc)
		return -1;

	d->alloc *= 2;
	newsize = sizeof(d->values[0]) * d->alloc;

	newkeys = realloc(d->keys, newsize);
	newvalues = realloc(d->values, newsize);
	if (newkeys == NULL || newvalues == NULL)
		return -1;
	d->keys = newkeys;
	d->values = newvalues;
	return 0;
}

static struct bencode *decode_dict(const char *data, size_t len, size_t *off,
	int level)
{
	struct bencode *key;
	struct bencode *value;
	size_t newoff = *off + 1;
	struct bencode_dict *d;

	d = alloc(BENCODE_DICT);
	if (d == NULL) {
		fprintf(stderr, "bencode: Not enough memory for dict\n");
		return NULL;
	}

	d->alloc = 4;
	d->keys = malloc(sizeof(d->keys[0]) * d->alloc);
	d->values = malloc(sizeof(d->values[0]) * d->alloc);
	if (d->keys == NULL || d->values == NULL) {
		free(d->keys);
		d->keys = NULL;
		free(d->values);
		d->values = NULL;
		fprintf(stderr, "bencode: No memory for dict keys/values\n");
		goto error;
	}

	while (newoff < len && data[newoff] != 'e') {
		if (d->n == d->alloc && resize_dict(d)) {
			fprintf(stderr, "bencode: Can not resize dict\n");
			goto error;
		}
		key = decode(data, len, &newoff, level);
		if (key == NULL)
			goto error;
		if (key->type != BENCODE_INT && key->type != BENCODE_STR) {
			ben_free(key);
			key = NULL;
			fprintf(stderr, "bencode: Invalid dict key type\n");
			goto error;
		}
		value = decode(data, len, &newoff, level);
		if (value == NULL) {
			ben_free(key);
			key = NULL;
			goto error;
		}
		d->keys[d->n] = key;
		d->values[d->n] = value;
		d->n++;
	}
	if (newoff >= len) {
		fprintf(stderr, "bencode: Dict not terminated: %zu\n", *off);
		goto error;
	}

	*off = newoff + 1;

	return (struct bencode *) d;

error:
	ben_free((struct bencode *) d);
	return NULL;
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
	struct bencode_int *b;
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
	return (struct bencode *) b;
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

static struct bencode *decode_list(const char *data, size_t len, size_t *off,
				   int level)
{
	struct bencode_list *l;
	size_t newoff = *off + 1;

	l = alloc(BENCODE_LIST);
	if (l == NULL) {
		fprintf(stderr, "bencode: No memory for list\n");
		return NULL;
	}

	l->alloc = 4;
	l->values = malloc(sizeof(l->values[0]) * l->alloc);
	if (l->values == NULL) {
		fprintf(stderr, "bencode: No memory for list values\n");
		goto error;
	}

	while (newoff < len && data[newoff] != 'e') {
		struct bencode *b;
		if (l->n == l->alloc && resize_list(l)) {
			fprintf(stderr, "bencode: Can not resize list: %zu\n", *off);
			goto error;
		}
		b = decode(data, len, &newoff, level);
		if (b == NULL)
			goto error;
		l->values[l->n] = b;
		l->n += 1;
	}

	if (newoff >= len) {
		fprintf(stderr, "bencode: List not terminated: %zu\n", *off);
		goto error;
	}

	*off = newoff + 1;

	return (struct bencode *) l;

error:
	ben_free((struct bencode *) l);
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
	struct bencode_str *b;
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
	b->s = malloc(datalen);
	if (b->s == NULL) {
		free(b);
		fprintf(stderr, "bencode: No memory for string\n");
		return NULL;
	}
	memcpy(b->s, data + newoff, datalen);
	b->len = datalen;

	*off = newoff + datalen;
	return (struct bencode *) b;
}

static struct bencode *decode(const char *data, size_t len, size_t *off,
			      int level)
{
	level++;
	if (level > 256)
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
		return decode_dict(data, len, off, level);
	case 'i':
		return decode_int(data, len, off);
	case 'l':
		return decode_list(data, len, off, level);
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

static void free_dict(struct bencode_dict *d)
{
	size_t pos;
	for (pos = 0; pos < d->n; pos++) {
		ben_free(d->keys[pos]);
		d->keys[pos] = NULL;
		ben_free(d->values[pos]);
		d->values[pos] = NULL;
	}
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
		free_dict((struct bencode_dict *) b);
		break;
	case BENCODE_INT:
		break;
	case BENCODE_LIST:
		free_list((struct bencode_list *) b);
		break;
	case BENCODE_STR:
		free(((struct bencode_str *) b)->s);
		break;
	default:
		fprintf(stderr, "bencode: invalid type: %d\n", b->type);
		exit(1);
	}

	memset(b, -1, type_size(b->type)); /* data poison */
	free(b);
}
