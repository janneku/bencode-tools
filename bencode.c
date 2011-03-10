#include <typevalidator/bencode.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>

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
		abort();
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
	if (b == NULL)
		return NULL;
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

	if (d->alloc == 0)
		d->alloc = 4;
	else
		d->alloc *= 2;
	newsize = sizeof(d->values[0]) * d->alloc;

	newkeys = realloc(d->keys, newsize);
	newvalues = realloc(d->values, newsize);
	if (newkeys == NULL || newvalues == NULL) {
		free(newkeys);
		free(newvalues);
		return -1;
	}
	d->keys = newkeys;
	d->values = newvalues;
	return 0;
}

static int bencmp(const struct bencode *a, const struct bencode *b)
{
	size_t cmplen;
	int ret;
	const struct bencode_str *sa;
	const struct bencode_str *sb;

	if (a->type != b->type)
		return (a->type == BENCODE_INT) ? -1 : 1;

	if (a->type == BENCODE_INT) {
		const struct bencode_int *ia = ben_int_const_cast(a);
		const struct bencode_int *ib = ben_int_const_cast(b);
		if (ia->ll < ib->ll)
			return -1;
		if (ib->ll < ia->ll)
			return 1;
		return 0;
	}

	sa = ben_str_const_cast(a);
	sb = ben_str_const_cast(b);
	cmplen = (sa->len <= sb->len) ? sa->len : sb->len;
	ret = memcmp(sa->s, sb->s, cmplen);
	if (sa->len == sb->len)
		return ret;
	if (ret)
		return ret;
	return (sa->len < sb->len) ? -1 : 1;
}

static int bencmpqsort(const void *a, const void *b)
{
	return bencmp(a, b);
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
		if (d->n > 0 && bencmp(d->keys[d->n - 1], key) != -1) {
			ben_free(key);
			key = NULL;
			fprintf(stderr, "bencode: Invalid key order or non-unique keys\n");
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

	if (buf[0] != '-' && !isdigit(buf[0]))
		return -1;

	errno = 0;
	*ll = strtoll(buf, &endptr, 10);
	if (errno == ERANGE || *endptr != 0)
		return -1;

	/*
	 * Demand a unique encoding for all integers.
	 * Zero may not begin with a (minus) sign.
	 * Non-zero integers may not have leading zeros in the encoding.
	 */
	if (buf[0] == '-' && buf[1] == '0')
		return -1;
	if (buf[0] == '0' && pos != (*off + 1))
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
	if (b == NULL)
		return NULL;
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

	if (list->alloc == 0)
		list->alloc = 4;
	else
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
	if (l == NULL)
		return NULL;

	while (newoff < len && data[newoff] != 'e') {
		struct bencode *b;
		b = decode(data, len, &newoff, level);
		if (b == NULL)
			goto error;
		if (ben_list_append((struct bencode *) l, b)) {
			ben_free(b);
			goto error;
		}
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
	struct bencode *b;
	size_t newoff = *off;

	/* Read the string length */
	datalen = read_size_t(data, len, &newoff, ':');
	if (datalen == -1)
		return invalid("invalid string length", *off);

	if ((newoff + datalen) > len)
		return invalid("string out of bounds", *off);

	/* Allocate string structure and copy data into it */
	b = ben_blob(data + newoff, datalen);
	if (b == NULL)
		return NULL;
	*off = newoff + datalen;
	return b;
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
	struct bencode *b;
	size_t off = 0;
	b = decode((const char *) data, len, &off, 0);
	if (b == NULL)
		return NULL;
	if (off != len) {
		ben_free(b);
		return NULL;
	}
	return b;
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

static int putonechar(char *data, size_t size, size_t *pos, char c)
{
	if (*pos >= size)
		return -1;
	data[*pos] = c;
	*pos += 1;
	return 0;
}

static int serialize(char *data, size_t size, size_t *pos,
		     const struct bencode *b)
{
	const struct bencode_dict *dict;
	const struct bencode_int *integer;
	const struct bencode_list *list;
	const struct bencode_str *s;
	struct bencode **keys;
	size_t i;
	int len;

	switch (b->type) {
	case BENCODE_BOOL:
		if ((*pos + 2) > size)
			return -1;
		data[*pos] = 'b';
		data[*pos + 1] = ben_bool_const_cast(b)->b ? '1' : '0';
		*pos += 2;
		return 0;

	case BENCODE_DICT:
		if (putonechar(data, size, pos, 'd'))
			return -1;

		dict = ben_dict_const_cast(b);

		keys = malloc(dict->n * sizeof(keys[0]));
		if (keys == NULL) {
			fprintf(stderr, "bencode: No memory for dict serialization\n");
			return -1;
		}
		for (i = 0; i < dict->n; i++)
			keys[i] = dict->keys[i];
		qsort(keys, dict->n, sizeof(keys[0]), bencmpqsort);

		for (i = 0; i < dict->n; i++) {
			struct bencode *value;
			if (serialize(data, size, pos, keys[i]))
				break;
			value = ben_dict_get(b, keys[i]);
			if (serialize(data, size, pos, value))
				break;
		}
		free(keys);
		keys = NULL;
		if (i < dict->n)
			return -1;

		return putonechar(data, size, pos, 'e');

	case BENCODE_INT:
		if (putonechar(data, size, pos, 'i'))
			return -1;

		integer = ben_int_const_cast(b);
		len = snprintf(data + *pos, size - *pos, "%lld", integer->ll);
		assert(len > 0);
		if ((*pos + len) > size)
			return -1;
		*pos += len;
		
		return putonechar(data, size, pos, 'e');

	case BENCODE_LIST:
		if (putonechar(data, size, pos, 'l'))
			return -1;

		list = ben_list_const_cast(b);
		for (i = 0; i < list->n; i++) {
			if (serialize(data, size, pos, list->values[i]))
				return -1;
		}

		return putonechar(data, size, pos, 'e');

	case BENCODE_STR:
		s = ben_str_const_cast(b);
		len = snprintf(data + *pos, size - *pos, "%zu", s->len);
		assert(len > 0);
		if ((*pos + len) > size)
			return -1;
		*pos += len;

		if (putonechar(data, size, pos, ':'))
			return -1;

		if ((*pos + s->len) > size)
			return -1;
		memcpy(data + *pos, s->s, s->len);
		return 0;

	default:
		fprintf(stderr, "bencode: serialization type %d not implemented\n", b->type);
		abort();
	}
}

static size_t get_size(const struct bencode *b)
{
	size_t pos;
	const struct bencode_dict *d;
	const struct bencode_int *i;
	const struct bencode_list *l;
	const struct bencode_str *s;
	size_t size = 0;
	char buf[1];

	switch (b->type) {
	case BENCODE_BOOL:
		return 2;
	case BENCODE_DICT:
		d = ben_dict_const_cast(b);
		for (pos = 0; pos < d->n; pos++) {
			size += get_size(d->keys[pos]);
			size += get_size(d->values[pos]);
		}
		return size + 2;
	case BENCODE_INT:
		i = ben_int_const_cast(b);
		return 2 + snprintf(buf, 0, "%lld", i->ll);
	case BENCODE_LIST:
		l = ben_list_const_cast(b);
		for (pos = 0; pos < l->n; pos++)
			size += get_size(l->values[pos]);
		return size + 2;
	case BENCODE_STR:
		s = ben_str_const_cast(b);
		return snprintf(buf, 0, "%zu", s->len) + 1 + s->len;
	default:
		fprintf(stderr, "bencode: invalid bencode type: %c\n", b->type);
		abort();
	}
}

size_t ben_encoded_size(const struct bencode *b)
{
	return get_size(b);
}

void *ben_encode(size_t *len, const struct bencode *b)
{
	size_t size = get_size(b);
	void *data = malloc(size);
	if (data == NULL) {
		fprintf(stderr, "bencode: No memory to encode\n");
		return NULL;
	}
	*len = 0;
	if (serialize(data, size, len, b)) {
		free(data);
		return NULL;
	}
	assert(*len == size);
	return data;
}

size_t ben_encode2(char *data, size_t maxlen, const struct bencode *b)
{
	size_t pos = 0;
	if (serialize(data, maxlen, &pos, b))
		return -1;
	return pos;
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
		abort();
	}

	memset(b, -1, type_size(b->type)); /* data poison */
	free(b);
}

struct bencode *ben_blob(const void *data, size_t len)
{
	struct bencode_str *b = alloc(BENCODE_STR);
	if (b == NULL)
		return NULL;
	/* Allocate one extra byte for zero termination for convenient use */
	b->s = malloc(len + 1);
	if (b->s == NULL) {
		free(b);
		return NULL;
	}
	memcpy(b->s, data, len);
	b->len = len;
	b->s[len] = 0;
	return (struct bencode *) b;
}

struct bencode *ben_bool(int boolean)
{
	struct bencode_bool *b = alloc(BENCODE_BOOL);
	if (b == NULL)
		return NULL;
	b->b = boolean ? 1 : 0;
	return (struct bencode *) b;
}

struct bencode *ben_dict(void)
{
	return alloc(BENCODE_DICT);
}

struct bencode *ben_dict_get(const struct bencode *dict, const struct bencode *key)
{
	const struct bencode_dict *d = ben_dict_const_cast(dict);
	size_t pos;
	for (pos = 0; pos < d->n; pos++) {
		if (bencmp(d->keys[pos], key) == 0)
			return d->values[pos];
	}
	return NULL;
}

static void replacewithlast(struct bencode **arr, size_t i, size_t n)
{
	arr[i] = arr[n - 1];
	arr[n - 1] = NULL;
}

struct bencode *ben_dict_pop(struct bencode *dict, const struct bencode *key)
{
	struct bencode_dict *d = ben_dict_cast(dict);
	size_t pos;
	for (pos = 0; pos < d->n; pos++) {
		if (bencmp(d->keys[pos], key) == 0) {
			struct bencode *value = d->values[pos];
			ben_free(d->keys[pos]);
			replacewithlast(d->keys, pos, d->n);
			replacewithlast(d->values, pos, d->n);
			d->n -= 1;
			return value;
		}
	}
	return NULL;
}

int ben_dict_set(struct bencode *dict, struct bencode *key, struct bencode *value)
{
	struct bencode_dict *d = ben_dict_cast(dict);

	assert(d->n <= d->alloc);
	if (d->n == d->alloc && resize_dict(d))
		return -1;

	ben_free(ben_dict_pop(dict, key));

	d->keys[d->n] = key;
	d->values[d->n] = value;
	d->n++;
	return 0;
}

struct bencode *ben_int(long long ll)
{
	struct bencode_int *b = alloc(BENCODE_INT);
	if (b == NULL)
		return NULL;
	b->ll = ll;
	return (struct bencode *) b;
}

struct bencode *ben_list(void)
{
	return alloc(BENCODE_LIST);
}

int ben_list_append(struct bencode *list, struct bencode *b)
{
	struct bencode_list *l = ben_list_cast(list);
	/* NULL pointer de-reference if the cast fails */
	assert(l->n <= l->alloc);
	if (l->n == l->alloc && resize_list(l))
		return -1;
	l->values[l->n] = b;
	l->n += 1;
	return 0;
}

struct bencode *ben_str(const char *s)
{
	return ben_blob(s, strlen(s));
}
