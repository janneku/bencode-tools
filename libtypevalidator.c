#include <typevalidator/bencode.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

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

static struct bencode *decode_int(const char *data, size_t len, size_t *off)
{
	/* fits all 64 bit integers */
	char buf[21];
	size_t slen;
	struct bencode *b;
	char *endptr;
	size_t pos;

	pos = find(data, len, *off, 'e');
	if (pos == -1)
		return overflow(*off);
	slen = pos - *off - 1;
	if (slen == 0 || slen >= sizeof buf)
		return invalid("bad int slen", *off);
	assert(slen < sizeof buf);
	memcpy(buf, &data[*off + 1], slen);
	buf[slen] = 0;
	b = alloc(BENCODE_INT);
	b->ll = strtoll(buf, &endptr, 10);
	if (*endptr != 0) {
		free(b);
		return invalid("bad int string", *off);
	}
	*off = pos;
	return b;
}

static struct bencode *decode_str(const char *data, size_t len, size_t *off)
{
	assert(0);
}

static struct bencode *decode(const char *data, size_t len, size_t *off, int l)
{
	l++;
	if (l > 1024)
		return NULL;
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
	case 'i':
		return decode_int(data, len, off);
	default:
		return invalid("unknown bencode type", *off);
	}
}

struct bencode *ben_decode(const void *data, size_t len)
{
	size_t off = 0;
	return decode((const char *) data, len, &off, 0);
}
