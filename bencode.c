#include <bencodetools/bencode.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>

#define bendie(fmt, args...) do { fprintf(stderr, "bencode: fatal error: " fmt, ## args); abort(); } while (0)
#define benwarn(fmt, args...) do { fprintf(stderr, "bencode: " fmt, ## args); } while (0)

#define MAX_ALLOC (((size_t) -1) / sizeof(struct bencode *) / 2)
#define DICT_MAX_ALLOC (((size_t) -1) / sizeof(struct bencode_dict_node) / 2)

struct decode {
	const char *data;
	const size_t len;
	size_t off;
	int error;
	int level;
	char c;
	int line;
};

/*
 * Buffer size for fitting all unsigned long long and long long integers,
 * assuming it is at most 64 bits. If long long is larger than 64 bits,
 * an error is produced when too large an integer is converted.
 */
#define LONGLONGSIZE 21

struct bencode_keyvalue {
	struct bencode *key;
	struct bencode *value;
};

static struct bencode *decode(struct decode *ctx);
static struct bencode *decode_printed(struct decode *ctx);

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
		bendie("Unknown type: %d\n", type);
	}
}

static void *alloc(int type)
{
	struct bencode *b = calloc(1, type_size(type));
	if (b == NULL)
		return NULL;
	b->type = type;
	return b;
}

static int insufficient(struct decode *ctx)
{
	ctx->error = BEN_INSUFFICIENT;
	return -1;
}

static int invalid(struct decode *ctx)
{
	ctx->error = BEN_INVALID;
	return -1;
}

static void *insufficient_ptr(struct decode *ctx)
{
	ctx->error = BEN_INSUFFICIENT;
	return NULL;
}

static void *invalid_ptr(struct decode *ctx)
{
	ctx->error = BEN_INVALID;
	return NULL;
}

static void *oom_ptr(struct decode *ctx)
{
	ctx->error = BEN_NO_MEMORY;
	return NULL;
}

static struct bencode *internal_blob(void *data, size_t len)
{
	struct bencode_str *b = alloc(BENCODE_STR);
	if (b == NULL)
		return NULL;
	b->s = data;
	b->len = len;
	assert(b->s[len] == 0);
	return (struct bencode *) b;
}

static char current_char(const struct decode *ctx)
{
	return ctx->data[ctx->off];
}

static int seek_char(struct decode *ctx)
{
	while (ctx->off < ctx->len) {
		if (!isspace(ctx->data[ctx->off]))
			return 0;
		if (ctx->data[ctx->off] == '\n')
			ctx->line++;
		ctx->off++;
	}
	return insufficient(ctx);
}

static int need_bytes(const struct decode *ctx, size_t n)
{
	return ((ctx->off + n) <= ctx->len) ? 0 : -1;
}

/*
 * Test if string 's' is located at current position.
 * Increment current position and return 0 if the string matches.
 * Returns -1 otherwise. The function avoids buffer overflow.
 */
static int try_match(struct decode *ctx, const char *s)
{
	size_t n = strlen(s);
	if (need_bytes(ctx, n))
		return -1;
	if (memcmp(ctx->data + ctx->off, s, n) != 0)
		return -1;
	ctx->off += n;
	return 0;
}

static int try_match_with_errors(struct decode *ctx, const char *s)
{
	size_t n = strlen(s);
	size_t left = ctx->len - ctx->off;

	assert(ctx->off <= ctx->len);

	if (left == 0)
		return insufficient(ctx);

	if (left < n) {
		if (memcmp(ctx->data + ctx->off, s, left) != 0)
			return invalid(ctx);
		return insufficient(ctx);
	}

	if (memcmp(ctx->data + ctx->off, s, n) != 0)
		return invalid(ctx);

	ctx->off += n;
	return 0;
}

static struct bencode *decode_bool(struct decode *ctx)
{
	struct bencode_bool *b;
	char value;
	char c;
	if (need_bytes(ctx, 2))
		return insufficient_ptr(ctx);
	ctx->off += 1;

	c = current_char(ctx);
	if (c != '0' && c != '1')
		return invalid_ptr(ctx);

	value = (c == '1');
	b = alloc(BENCODE_BOOL);
	if (b == NULL)
		return oom_ptr(ctx);

	b->b = value;
	ctx->off += 1;
	return (struct bencode *) b;
}

static size_t hash_bucket(long long hash, const struct bencode_dict *d)
{
	return hash & (d->alloc - 1);
}

static size_t hash_bucket_head(long long hash, const struct bencode_dict *d)
{
	if (d->buckets == NULL)
		return -1;
	return d->buckets[hash_bucket(hash, d)];
}

static int resize_dict(struct bencode_dict *d)
{
	size_t *newbuckets;
	struct bencode_dict_node *newnodes;;
	size_t newalloc;
	size_t pos;

	if (d->alloc >= DICT_MAX_ALLOC)
		return -1;

	if (d->alloc == 0)
		newalloc = 4;
	else
		newalloc = d->alloc * 2;

	/* size must be a power of two */
	assert((newalloc & (newalloc - 1)) == 0);

	newbuckets = realloc(d->buckets, sizeof(newbuckets[0]) * newalloc);
	newnodes = realloc(d->nodes, sizeof(newnodes[0]) * newalloc);
	if (newnodes == NULL || newbuckets == NULL) {
		free(newnodes);
		free(newbuckets);
		return -1;
	}

	d->alloc = newalloc;
	d->buckets = newbuckets;
	d->nodes = newnodes;

	/* Clear all buckets */
	memset(d->buckets, -1, d->alloc * sizeof(d->buckets[0]));

	/* Reinsert nodes into buckets */
	for (pos = 0; pos < d->n; pos++) {
		struct bencode_dict_node *node = &d->nodes[pos];
		size_t bucket = hash_bucket(node->hash, d);
		node->next = d->buckets[bucket];
		d->buckets[bucket] = pos;
	}

	return 0;
}

int ben_cmp(const struct bencode *a, const struct bencode *b)
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

int ben_cmp_qsort(const void *a, const void *b)
{
	const struct bencode *akey = ((const struct bencode_keyvalue *) a)->key;
	const struct bencode *bkey = ((const struct bencode_keyvalue *) b)->key;
	return ben_cmp(akey, bkey);
}

/* The string/binary object hash is copied from Python */
static long long str_hash(const unsigned char *s, size_t len)
{
	long long hash;
	size_t i;
	if (len == 0)
		return 0;
	hash = s[0] << 7;
	for (i = 0; i < len; i++)
		hash = (1000003 * hash) ^ s[i];
	hash ^= len;
	if (hash == -1)
		hash = -2;
	return hash;
}

long long ben_str_hash(const struct bencode *b)
{
	const struct bencode_str *bstr = ben_str_const_cast(b);
	const unsigned char *s = (unsigned char *) bstr->s;
	return str_hash(s, bstr->len);
}

long long ben_int_hash(const struct bencode *b)
{
	long long x = ben_int_const_cast(b)->ll;
	return (x == -1) ? -2 : x;
}

long long ben_hash(const struct bencode *b)
{
	switch (b->type) {
	case BENCODE_INT:
		return ben_int_hash(b);
	case BENCODE_STR:
		return ben_str_hash(b);
	default:
		bendie("hash: Invalid type: %d\n", b->type);
	}		
}

static struct bencode *decode_dict(struct decode *ctx)
{
	struct bencode *key;
	struct bencode *lastkey = NULL;
	struct bencode *value;
	struct bencode_dict *d;

	d = alloc(BENCODE_DICT);
	if (d == NULL) {
		benwarn("Not enough memory for dict\n");
		return oom_ptr(ctx);
	}

	ctx->off += 1;

	while (ctx->off < ctx->len && current_char(ctx) != 'e') {
		if (d->n == d->alloc && resize_dict(d)) {
			benwarn("Can not resize dict\n");
			ctx->error = BEN_NO_MEMORY;
			goto error;
		}
		key = decode(ctx);
		if (key == NULL)
			goto error;
		if (key->type != BENCODE_INT && key->type != BENCODE_STR) {
			ben_free(key);
			key = NULL;
			ctx->error = BEN_INVALID;
			benwarn("Invalid dict key type\n");
			goto error;
		}

		if (lastkey != NULL && ben_cmp(lastkey, key) != -1) {
			ben_free(key);
			key = NULL;
			ctx->error = BEN_INVALID;
			goto error;
		}

		value = decode(ctx);
		if (value == NULL) {
			ben_free(key);
			key = NULL;
			goto error;
		}

		ben_dict_set((struct bencode *) d, key, value);
		lastkey = key;
	}
	if (ctx->off >= ctx->len) {
		ctx->error = BEN_INSUFFICIENT;
		goto error;
	}

	ctx->off += 1;

	return (struct bencode *) d;

error:
	ben_free((struct bencode *) d);
	return NULL;
}

/* off is the position of first number in */
static int read_long_long(long long *ll, struct decode *ctx, int c)
{
	char buf[LONGLONGSIZE]; /* fits all 64 bit integers */
	size_t pos;
	char *endptr;
	size_t slen;

	pos = find(ctx->data, ctx->len, ctx->off, c);
	if (pos == -1)
		return insufficient(ctx);

	slen = pos - ctx->off;
	if (slen == 0 || slen >= sizeof buf)
		return invalid(ctx);

	assert(slen < sizeof buf);
	memcpy(buf, ctx->data + ctx->off, slen);
	buf[slen] = 0;

	if (buf[0] != '-' && !isdigit(buf[0]))
		return invalid(ctx);

	errno = 0;
	*ll = strtoll(buf, &endptr, 10);
	if (errno == ERANGE || *endptr != 0)
		return invalid(ctx);

	/*
	 * Demand a unique encoding for all integers.
	 * Zero may not begin with a (minus) sign.
	 * Non-zero integers may not have leading zeros in the encoding.
	 */
	if (buf[0] == '-' && buf[1] == '0')
		return invalid(ctx);
	if (buf[0] == '0' && pos != (ctx->off + 1))
		return invalid(ctx);

	ctx->off = pos + 1;
	return 0;
}

static struct bencode *decode_int(struct decode *ctx)
{
	struct bencode_int *b;
	long long ll;
	ctx->off += 1;
	if (read_long_long(&ll, ctx, 'e'))
		return NULL;
	b = alloc(BENCODE_INT);
	if (b == NULL)
		return oom_ptr(ctx);
	b->ll = ll;
	return (struct bencode *) b;
}

static int resize_list(struct bencode_list *list)
{
	struct bencode **newvalues;
	size_t newalloc;
	size_t newsize;

	if (list->alloc >= MAX_ALLOC)
		return -1;

	if (list->alloc == 0)
		newalloc = 4;
	else
		newalloc = list->alloc * 2;
	newsize = sizeof(list->values[0]) * newalloc;
	newvalues = realloc(list->values, newsize);
	if (newvalues == NULL)
		return -1;
	list->alloc = newalloc;
	list->values = newvalues;
	return 0;
}

static struct bencode *decode_list(struct decode *ctx)
{
	struct bencode_list *l = alloc(BENCODE_LIST);
	if (l == NULL)
		return oom_ptr(ctx);

	ctx->off += 1;

	while (ctx->off < ctx->len && current_char(ctx) != 'e') {
		struct bencode *b = decode(ctx);
		if (b == NULL)
			goto error;
		if (ben_list_append((struct bencode *) l, b)) {
			ben_free(b);
			ctx->error = BEN_NO_MEMORY;
			goto error;
		}
	}

	if (ctx->off >= ctx->len) {
		ctx->error = BEN_INSUFFICIENT;
		goto error;
	}

	ctx->off += 1;
	return (struct bencode *) l;

error:
	ben_free((struct bencode *) l);
	return NULL;
}

static size_t read_size_t(struct decode *ctx, int c)
{
	long long ll;
	size_t s;
	if (read_long_long(&ll, ctx, c))
		return -1;
	if (ll < 0)
		return invalid(ctx);
	/*
	 * Test that information is not lost when converting from long long
	 * to size_t
	 */
	s = (size_t) ll;
	if (ll != (long long) s)
		return invalid(ctx);
	return s;
}

static struct bencode *decode_str(struct decode *ctx)
{
	struct bencode *b;
	size_t datalen = read_size_t(ctx, ':'); /* Read the string length */
	if (datalen == -1)
		return NULL;

	if (need_bytes(ctx, datalen))
		return insufficient_ptr(ctx);

	/* Allocate string structure and copy data into it */
	b = ben_blob(ctx->data + ctx->off, datalen);
	ctx->off += datalen;
	return b;
}

static struct bencode *decode(struct decode *ctx)
{
	struct bencode *b;
	ctx->level++;
	if (ctx->level > 256)
		return invalid_ptr(ctx);

	if (ctx->off == ctx->len)
		return insufficient_ptr(ctx);

	assert (ctx->off < ctx->len);
	switch (current_char(ctx)) {
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
		b = decode_str(ctx);
		break;
	case 'b':
		b = decode_bool(ctx);
		break;
	case 'd':
		b = decode_dict(ctx);
		break;
	case 'i':
		b = decode_int(ctx);
		break;
	case 'l':
		b = decode_list(ctx);
		break;
	default:
		return invalid_ptr(ctx);
	}
	ctx->level--;
	return b;
}

struct bencode *ben_decode(const void *data, size_t len)
{
	struct decode ctx = {.data = data, .len = len};
	struct bencode *b = decode(&ctx);
	if (b != NULL && ctx.off != len) {
		ben_free(b);
		return NULL;
	}
	return b;
}

struct bencode *ben_decode2(const void *data, size_t len, size_t *off, int *error)
{
	struct decode ctx = {.data = data, .len = len, .off = *off};
	struct bencode *b = decode(&ctx);
	*off = ctx.off;
	if (error != NULL) {
		assert((b != NULL) ^ (ctx.error != 0));
		*error = ctx.error;
	}
	return b;
}

static struct bencode *decode_printed_bool(struct decode *ctx)
{
	struct bencode *b;
	int bval = -1;

	if (try_match(ctx, "True")) {	
		if (need_bytes(ctx, 4))
			return insufficient_ptr(ctx);
	} else {
		bval = 1;
	}

	if (bval < 0) {
		/* It's not 'True', so it can only be 'False'. Verify it. */
		if (try_match_with_errors(ctx, "False"))
			return NULL;
		bval = 0;
	}

	assert(bval == 0 || bval == 1);
	b = ben_bool(bval);
	if (b == NULL)
		return oom_ptr(ctx);
	return b;
}

static struct bencode *decode_printed_dict(struct decode *ctx)
{
	struct bencode *d = ben_dict();
	int dictstate = 0; /* 0 == key, 1 == colon, 2 == value, 3 == comma */
	struct bencode *key = NULL;
	struct bencode *value = NULL;

	if (d == NULL)
		return oom_ptr(ctx);

	ctx->off++;

	while (1) {
		if (seek_char(ctx))
			goto nullpath;

		switch (dictstate) {
		case 0:
			if (current_char(ctx) == '}') {
				ctx->off++;
				goto exit;
			}
			key = decode_printed(ctx);
			if (key == NULL)
				goto nullpath;
			dictstate = 1;
			break;
		case 1:
			if (current_char(ctx) != ':')
				goto invalidpath;
			ctx->off++;
			dictstate = 2;
			break;
		case 2:
			value = decode_printed(ctx);
			if (value == NULL)
				goto nullpath;
			assert(key != NULL);
			if (ben_dict_set(d, key, value)) {
				ben_free(key);
				ben_free(value);
				ben_free(d);
				return oom_ptr(ctx);
			}
			key = NULL;
			value = NULL;
			dictstate = 3;
			break;
		case 3:
			if (current_char(ctx) == '}') {
				ctx->off++;
				goto exit;
			}
			if (current_char(ctx) != ',')
				goto invalidpath;
			ctx->off++;
			dictstate = 0;
			break;
		default:
			bendie("Invalid dictstate: %d\n", dictstate);
		}
	}

exit:
	return d;

invalidpath:
	ben_free(key);
	ben_free(value);
	ben_free(d);
	return invalid_ptr(ctx);

nullpath:
	ben_free(key);
	ben_free(value);
	ben_free(d);
	return NULL;
}

static struct bencode *decode_printed_int(struct decode *ctx)
{
	long long ll;
	char buf[LONGLONGSIZE];
	char *end;
	size_t pos = 0;
	struct bencode *b;
	int gotzero = 0;
	int base = 10;
	int neg = 0;

	if (current_char(ctx) == '-') {
		neg = 1;
		ctx->off++;
	}
	if (ctx->off == ctx->len)
		return insufficient_ptr(ctx);

	if (current_char(ctx) == '0') {
		buf[pos] = '0';
		pos++;
		ctx->off++;
		gotzero = 1;
	}

	if (gotzero) {
		if (ctx->off == ctx->len) {
			ll = 0;
			goto returnwithval;
		}
		if (current_char(ctx) == 'x') {
			pos = 0;
			base = 16;
			ctx->off++;
			if (ctx->off == ctx->len)
				return insufficient_ptr(ctx);
		} else if (isdigit(current_char(ctx))) {
			base = 8;
		}
	} else {
		if (ctx->off == ctx->len)
			return insufficient_ptr(ctx);
	}

	while (ctx->off < ctx->len && pos < sizeof buf) {
		char c = current_char(ctx);
		if (base == 16) {
			if (!isxdigit(c))
				break;
		} else {
			if (!isdigit(c))
				break;
		}
		buf[pos] = c;
		pos++;
		ctx->off++;
	}
	if (pos == 0 || pos == sizeof buf)
		return invalid_ptr(ctx);
	buf[pos] = 0;
	ll = strtoll(buf, &end, base);
	if (*end != 0)
		return invalid_ptr(ctx);

returnwithval:
	if (neg)
		ll = -ll;
	b = ben_int(ll);
	if (b == NULL)
		return oom_ptr(ctx);
	return b;
}

static struct bencode *decode_printed_list(struct decode *ctx)
{
	struct bencode *l = ben_list();
	int requirecomma = 0;
	struct bencode *b;

	if (l == NULL)
		return oom_ptr(ctx);

	ctx->off++;

	while (ctx->off < ctx->len) {
		if (seek_char(ctx)) {
			ben_free(l);
			return NULL;
		}
		if (current_char(ctx) == ']') {
			ctx->off++;
			break;
		}
		if (requirecomma) {
			if (current_char(ctx) != ',') {
				ben_free(l);
				return invalid_ptr(ctx);
			}
			ctx->off++;
			requirecomma = 0;
		} else {
			b = decode_printed(ctx);
			if (b == NULL) {
				ben_free(l);
				return NULL;
			}
			if (ben_list_append(l, b)) {
				ben_free(l);
				return oom_ptr(ctx);
			}
			requirecomma = 1;
		}
	}
	return l;
}

static struct bencode *decode_printed_str(struct decode *ctx)
{
	size_t pos;
	char *s = NULL;
	size_t len = 0;
	char initial = current_char(ctx);
	struct bencode *b;

	ctx->off++;
	pos = ctx->off;
	while (pos < ctx->len) {
		char c = ctx->data[pos];
		if (!isprint(c))
			return invalid_ptr(ctx);
		if (c == initial)
			break;
		len++;
		pos++;
		if (c != '\\')
			continue; /* Normal printable char, e.g. 'a' */
		/* Handle '\\' */
		if (pos == ctx->len)
			return insufficient_ptr(ctx);

		c = ctx->data[pos];
		pos++;
		if (c == 'x') {
			/* hexadecimal value: \xHH */
			pos += 2;
		}
	}
	if (pos >= ctx->len)
		return insufficient_ptr(ctx);

	s = malloc(len + 1);
	if (s == NULL)
		return oom_ptr(ctx);

	pos = 0;
	while (ctx->off < ctx->len) {
		char c = current_char(ctx);
		assert(isprint(c));
		if (c == initial)
			break;
		assert(pos < len);
		ctx->off++;
		if (c != '\\') {
			s[pos] = c;
			pos++;
			continue; /* Normal printable char, e.g. 'a' */
		}
		/* Handle '\\' */

		/*
		 * Note, we do assert because we have already verified in the
		 * previous loop that there is sufficient data.
		 */
		assert(ctx->off != ctx->len);
		c = current_char(ctx);
		ctx->off++;
		if (c == 'x') {
			/* hexadecimal value: \xHH */
			char *end;
			unsigned long x;
			char buf[3];
			assert((ctx->off + 1) < ctx->len);
			buf[0] = ctx->data[ctx->off + 0];
			buf[1] = ctx->data[ctx->off + 1];
			buf[2] = 0;
			ctx->off += 2;
			x = strtoul(buf, &end, 16);
			if (*end != 0)
				goto invalid;
			assert(x < 256);
			c = (char) x;
		}
		s[pos] = c;
		pos++;
	}
	assert(pos == len);
	if (ctx->off >= ctx->len)
		return insufficient_ptr(ctx);
	ctx->off++;

	s[pos] = 0; /* the area must always be zero terminated! */

	b = internal_blob(s, len);
	if (b == NULL) {
		free(s);
		return oom_ptr(ctx);
	}
	return b;

invalid:
	free(s);
	return invalid_ptr(ctx);
}

static struct bencode *decode_printed(struct decode *ctx)
{
	struct bencode *b;

	ctx->level++;
	if (ctx->level > 256)
		return invalid_ptr(ctx);
	
	if (seek_char(ctx))
		return NULL;

	switch (current_char(ctx)) {
	case '\'':
	case '"':
		b = decode_printed_str(ctx);
		break;
	case '-':
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
		b = decode_printed_int(ctx);
		break;
	case 'F':
	case 'T':
		b = decode_printed_bool(ctx);
		break;
	case '[':
		b = decode_printed_list(ctx);
		break;
	case '{':
		b = decode_printed_dict(ctx);
		break;
	default:
		return invalid_ptr(ctx);
	}
	ctx->level--;
	return b;
}

struct bencode *ben_decode_printed(const void *data, size_t len)
{
	struct decode ctx = {.data = data, .len = len};
	return decode_printed(&ctx);
}

struct bencode *ben_decode_printed2(const void *data, size_t len, size_t *off, struct bencode_error *error)
{
	struct decode ctx = {.data = data, .len = len, .off = *off};
	struct bencode *b = decode_printed(&ctx);
	*off = ctx.off;
	if (error != NULL) {
		assert((b != NULL) ^ (ctx.error != 0));
		error->error = ctx.error;
		if (b != NULL) {
			error->off = 0;
			error->line = 0;
		} else {
			error->off = ctx.off;
			error->line = ctx.line;
		}
	}
	return b;
}

static void free_dict(struct bencode_dict *d)
{
	size_t pos;
	for (pos = 0; pos < d->n; pos++) {
		ben_free(d->nodes[pos].key);
		d->nodes[pos].key = NULL;
		ben_free(d->nodes[pos].value);
		d->nodes[pos].value = NULL;
	}
	d->n = -1;
	d->alloc = -1;
	free(d->buckets);
	d->buckets = NULL;
	free(d->nodes);
	d->nodes = NULL;
}

static void free_list(struct bencode_list *list)
{
	size_t pos;
	for (pos = 0; pos < list->n; pos++) {
		ben_free(list->values[pos]);
		list->values[pos] = NULL;
	}
	free(list->values);
}

static int putonechar(char *data, size_t size, size_t *pos, char c)
{
	if (*pos >= size)
		return -1;
	data[*pos] = c;
	*pos += 1;
	return 0;
}

static int puthexchar(char *data, size_t size, size_t *pos, unsigned char hex)
{
	char buf[5];
	int len = snprintf(buf, sizeof buf, "\\x%.2x", hex);
	assert(len == 4);
	if ((*pos + len) > size)
		return -1;
	memcpy(data + *pos, buf, len);
	*pos += len;
	return 0;
}

static int putlonglong(char *data, size_t size, size_t *pos, long long ll)
{
	char buf[LONGLONGSIZE];
	int len = snprintf(buf, sizeof buf, "%lld", ll);
	assert(len > 0);
	if ((*pos + len) > size)
		return -1;
	memcpy(data + *pos, buf, len);
	*pos += len;
	return 0;
}

static int putunsignedlonglong(char *data, size_t size, size_t *pos,
			       unsigned long long llu)
{
	char buf[LONGLONGSIZE];
	int len = snprintf(buf, sizeof buf, "%llu", llu);
	assert(len > 0);
	if ((*pos + len) > size)
		return -1;
	memcpy(data + *pos, buf, len);
	*pos += len;
	return 0;
}

static int putstr(char *data, size_t size, size_t *pos, char *s)
{
	size_t len = strlen(s);
	if (*pos + len > size)
		return -1;
	memcpy(data + *pos, s, len);
	*pos += len;
	return 0;
}

static int print(char *data, size_t size, size_t *pos, const struct bencode *b)
{
	const struct bencode_bool *boolean;
	const struct bencode_dict *dict;
	const struct bencode_int *integer;
	const struct bencode_list *list;
	const struct bencode_str *s;
	size_t i;
	int len;
	struct bencode_keyvalue *pairs;

	switch (b->type) {
	case BENCODE_BOOL:
		boolean = ben_bool_const_cast(b);
		len = boolean->b ? 4 : 5;
		if (*pos + len > size)
			return -1;
		memcpy(data + *pos, (len == 4) ? "True" : "False", len);
		*pos += len;
		return 0;

	case BENCODE_DICT:
		if (putonechar(data, size, pos, '{'))
			return -1;

		dict = ben_dict_const_cast(b);

		pairs = malloc(dict->n * sizeof(pairs[0]));
		if (pairs == NULL) {
			benwarn("No memory for dict serialization\n");
			return -1;
		}
		for (i = 0; i < dict->n; i++) {
			pairs[i].key = dict->nodes[i].key;
			pairs[i].value = dict->nodes[i].value;
		}
		qsort(pairs, dict->n, sizeof(pairs[0]), ben_cmp_qsort);

		for (i = 0; i < dict->n; i++) {
			if (print(data, size, pos, pairs[i].key))
				break;
			if (putstr(data, size, pos, ": "))
				break;
			if (print(data, size, pos, pairs[i].value))
				break;
			if (i < (dict->n - 1)) {
				if (putstr(data, size, pos, ", "))
					break;
			}
		}
		free(pairs);
		pairs = NULL;
		if (i < dict->n)
			return -1;

		return putonechar(data, size, pos, '}');

	case BENCODE_INT:
		integer = ben_int_const_cast(b);

		if (putlonglong(data, size, pos, integer->ll))
			return -1;

		return 0;

	case BENCODE_LIST:
		if (putonechar(data, size, pos, '['))
			return -1;
		list = ben_list_const_cast(b);
		for (i = 0; i < list->n; i++) {
			if (print(data, size, pos, list->values[i]))
				return -1;
			if (i < (list->n - 1) && putstr(data, size, pos, ", "))
				return -1;
		}
		return putonechar(data, size, pos, ']');

	case BENCODE_STR:
		s = ben_str_const_cast(b);
		if (putonechar(data, size, pos, '\''))
			return -1;
		for (i = 0; i < s->len; i++) {
			if (!isprint(s->s[i])) {
				if (puthexchar(data, size, pos, s->s[i]))
					return -1;
				continue;
			}

			switch (s->s[i]) {
			case '\'':
			case '\\':
				/* Need escape character */
				if (putonechar(data, size, pos, '\\'))
					return -1;
			default:
				if (putonechar(data, size, pos, s->s[i]))
					return -1;
				break;
			}
		}
		return putonechar(data, size, pos, '\'');
	default:
		bendie("serialization type %d not implemented\n", b->type);
	}
}

static size_t get_printed_size(const struct bencode *b)
{
	size_t pos;
	const struct bencode_bool *boolean;
	const struct bencode_dict *d;
	const struct bencode_int *i;
	const struct bencode_list *l;
	const struct bencode_str *s;
	size_t size = 0;
	char buf[1];

	switch (b->type) {
	case BENCODE_BOOL:
		boolean = ben_bool_const_cast(b);
		return boolean->b ? 4 : 5; /* "True" and "False" */
	case BENCODE_DICT:
		size += 1; /* "{" */
		d = ben_dict_const_cast(b);
		for (pos = 0; pos < d->n; pos++) {
			size += get_printed_size(d->nodes[pos].key);
			size += 2; /* ": " */
			size += get_printed_size(d->nodes[pos].value);
			if (pos < (d->n - 1))
				size += 2; /* ", " */
		}
		size += 1; /* "}" */
		return size;
	case BENCODE_INT:
		i = ben_int_const_cast(b);
		return snprintf(buf, 0, "%lld", i->ll);
	case BENCODE_LIST:
		size += 1; /* "[" */
		l = ben_list_const_cast(b);
		for (pos = 0; pos < l->n; pos++) {
			size += get_printed_size(l->values[pos]);
			if (pos < (l->n - 1))
				size += 2; /* ", " */
		}
		size += 1; /* "]" */
		return size;
	case BENCODE_STR:
		s = ben_str_const_cast(b);
		size += 1; /* ' */
		for (pos = 0; pos < s->len; pos++) {
			if (!isprint(s->s[pos])) {
				size += 4; /* "\xDD" */
				continue;
			}
			switch (s->s[pos]) {
			case '\'':
			case '\\':
				size += 2; /* escaped characters */
				break;
			default:
				size += 1;
				break;
			}
		}
		size += 1; /* ' */
		return size;
	default:
		bendie("Unknown type: %c\n", b->type);
	}
}

static int serialize(char *data, size_t size, size_t *pos,
		     const struct bencode *b)
{
	const struct bencode_dict *dict;
	const struct bencode_int *integer;
	const struct bencode_list *list;
	const struct bencode_str *s;
	size_t i;
	struct bencode_keyvalue *pairs;

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

		pairs = malloc(dict->n * sizeof(pairs[0]));
		if (pairs == NULL) {
			benwarn("No memory for dict serialization\n");
			return -1;
		}
		for (i = 0; i < dict->n; i++) {
			pairs[i].key = dict->nodes[i].key;
			pairs[i].value = dict->nodes[i].value;
		}
		qsort(pairs, dict->n, sizeof(pairs[0]), ben_cmp_qsort);

		for (i = 0; i < dict->n; i++) {
			if (serialize(data, size, pos, pairs[i].key))
				break;
			if (serialize(data, size, pos, pairs[i].value))
				break;
		}
		free(pairs);
		pairs = NULL;
		if (i < dict->n)
			return -1;

		return putonechar(data, size, pos, 'e');

	case BENCODE_INT:
		if (putonechar(data, size, pos, 'i'))
			return -1;
		integer = ben_int_const_cast(b);
		if (putlonglong(data, size, pos, integer->ll))
			return -1;
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
		if (putunsignedlonglong(data, size, pos, ((long long) s->len)))
			return -1;
		if (putonechar(data, size, pos, ':'))
			return -1;
		if ((*pos + s->len) > size)
			return -1;
		memcpy(data + *pos, s->s, s->len);
		*pos += s->len;
		return 0;

	default:
		bendie("serialization type %d not implemented\n", b->type);
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
			size += get_size(d->nodes[pos].key);
			size += get_size(d->nodes[pos].value);
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
		bendie("Unknown type: %c\n", b->type);
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
		benwarn("No memory to encode\n");
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
		bendie("invalid type: %d\n", b->type);
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
	long long hash = ben_hash(key);
	size_t pos = hash_bucket_head(hash, d);
	while (pos != -1) {
		assert(pos < d->n);
		if (d->nodes[pos].hash == hash &&
		    ben_cmp(d->nodes[pos].key, key) == 0)
			return d->nodes[pos].value;
		pos = d->nodes[pos].next;
	}
	return NULL;
}

/*
 * Note, we do not re-allocate memory, so one may not call ben_free for these
 * instances. These are only used to optimize speed.
 */
static void inplace_ben_str(struct bencode_str *b, const char *s, size_t len)
{
	b->type = BENCODE_STR;
	b->len = len;
	b->s = (char *) s;
}
static void inplace_ben_int(struct bencode_int *i, long long ll)
{
	i->type = BENCODE_INT;
	i->ll = ll;
}

struct bencode *ben_dict_get_by_str(const struct bencode *dict, const char *key)
{
	struct bencode_str s;
	inplace_ben_str(&s, key, strlen(key));
	return ben_dict_get(dict, (struct bencode *) &s);
}

struct bencode *ben_dict_get_by_int(const struct bencode *dict, long long key)
{
	struct bencode_int i;
	inplace_ben_int(&i, key);
	return ben_dict_get(dict, (struct bencode *) &i);
}

static size_t dict_find_pos(struct bencode_dict *d,
			    const struct bencode *key, long long hash)
{
	size_t pos = hash_bucket_head(hash, d);
	while (pos != -1) {
		assert(pos < d->n);
		if (d->nodes[pos].hash == hash &&
		    ben_cmp(d->nodes[pos].key, key) == 0)
			break;
		pos = d->nodes[pos].next;
	}
	return pos;
}

static void dict_unlink(struct bencode_dict *d, size_t bucket, size_t unlinkpos)
{
	size_t pos = d->buckets[bucket];
	size_t next;
	size_t nextnext;

	assert(unlinkpos < d->n);

	if (pos == unlinkpos) {
		next = d->nodes[unlinkpos].next;
		assert(next < d->n || next == -1);
		d->buckets[bucket] = next;
		return;
	}
	while (pos != -1) {
		assert(pos < d->n);
		next = d->nodes[pos].next;
		if (next == unlinkpos) {
			nextnext = d->nodes[next].next;
			assert(nextnext < d->n || nextnext == -1);
			d->nodes[pos].next = nextnext;
			return;
		}
		pos = next;
	}
	bendie("Key should have been found. Can not unlink position %zu.\n", unlinkpos);
}

/* Remove node from the linked list, if found */
static struct bencode *dict_pop(struct bencode_dict *d, 
				const struct bencode *key, long long hash)
{
	struct bencode *value;
	size_t removebucket = hash_bucket(hash, d);
	size_t tailpos = d->n - 1;
	size_t tailhash = d->nodes[tailpos].hash;
	size_t tailbucket = hash_bucket(tailhash, d);
	size_t removepos;

	removepos = dict_find_pos(d, key, hash);
	if (removepos == -1)
		return NULL;
	key = NULL; /* avoid using the pointer again, it may not be valid */

	/*
	 * WARNING: complicated code follows.
	 *
	 * First, unlink the node to be removed and the tail node.
	 * We will actually later swap the positions of removed node and
	 * tail node inside the d->nodes array. We want to preserve
	 * d->nodes array in a state where positions from 0 to (d->n - 1)
	 * are always occupied with a valid node. This is done to make
	 * dictionary walk fast by simply walking positions 0 to (d->n - 1)
	 * in a for loop.
	 */
	dict_unlink(d, removebucket, removepos);
	if (removepos != tailpos)
		dict_unlink(d, tailbucket, tailpos);

	/* Then read the removed node and free its key */
	value = d->nodes[removepos].value;
	ben_free(d->nodes[removepos].key);

	/* Then re-insert the unliked tail node in the place of removed node */
	d->nodes[removepos] = d->nodes[tailpos];
	memset(&d->nodes[tailpos], 0, sizeof d->nodes[tailpos]); /* poison */
	d->nodes[tailpos].next = ((size_t) -1) / 2;

	/*
	 * Then re-link the tail node to its bucket, unless the tail node
	 * was the one to be removed.
	 */
	if (removepos != tailpos) {
		d->nodes[removepos].next = d->buckets[tailbucket];
		d->buckets[tailbucket] = removepos;
	}

	d->n -= 1;
	return value;
}

struct bencode *ben_dict_pop(struct bencode *dict, const struct bencode *key)
{
	struct bencode_dict *d = ben_dict_cast(dict);
	return dict_pop(d, key, ben_hash(key));
}

struct bencode *ben_dict_pop_by_str(struct bencode *dict, const char *key)
{
	struct bencode_str s;
	inplace_ben_str(&s, key, strlen(key));
	return ben_dict_pop(dict, (struct bencode *) &s);
}

struct bencode *ben_dict_pop_by_int(struct bencode *dict, long long key)
{
	struct bencode_int i;
	inplace_ben_int(&i, key);
	return ben_dict_pop(dict, (struct bencode *) &i);
}

/* This can be used from the ben_dict_for_each() iterator */
struct bencode *ben_dict_pop_current(struct bencode *dict, size_t *pos)
{
	struct bencode_dict *d = ben_dict_cast(dict);
	struct bencode *value = ben_dict_pop(dict, d->nodes[*pos].key);
	(*pos)--;
	return value;
}

int ben_dict_set(struct bencode *dict, struct bencode *key, struct bencode *value)
{
	struct bencode_dict *d = ben_dict_cast(dict);
	long long hash = ben_hash(key);
	size_t bucket;
	size_t pos;

	assert(value != NULL);

	pos = hash_bucket_head(hash, d);
	for (; pos != -1; pos = d->nodes[pos].next) {
		assert(pos < d->n);
		if (d->nodes[pos].hash != hash || ben_cmp(d->nodes[pos].key, key) != 0)
			continue;
		ben_free(d->nodes[pos].key);
		ben_free(d->nodes[pos].value);
		d->nodes[pos].key = key;
		d->nodes[pos].value = value;
		/* 'hash' and 'next' members stay the same */
		return 0;
	}

	assert(d->n <= d->alloc);
	if (d->n == d->alloc && resize_dict(d))
		return -1;

	bucket = hash_bucket(hash, d);
	pos = d->n;
	d->nodes[pos] = (struct bencode_dict_node) {.hash = hash,
						    .key = key,
						    .value = value,
						    .next = d->buckets[bucket]};
	d->n++;
	d->buckets[bucket] = pos;
	return 0;
}

int ben_dict_set_by_str(struct bencode *dict, const char *key, struct bencode *value)
{
	struct bencode *bkey = ben_str(key);
	if (bkey == NULL)
		return -1;
	if (ben_dict_set(dict, bkey, value)) {
		ben_free(bkey);
		return -1;
	}
	return 0;
}

int ben_dict_set_str_by_str(struct bencode *dict, const char *key, const char *value)
{
	struct bencode *bkey = ben_str(key);
	struct bencode *bvalue = ben_str(value);
	if (bkey == NULL || bvalue == NULL) {
		ben_free(bkey);
		ben_free(bvalue);
		return -1;
	}
	if (ben_dict_set(dict, bkey, bvalue)) {
		ben_free(bkey);
		ben_free(bvalue);
		return -1;
	}
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
	assert(b != NULL);
	l->values[l->n] = b;
	l->n += 1;
	return 0;
}

int ben_list_append_str(struct bencode *list, const char *s)
{
	struct bencode *bs = ben_str(s);
	if (bs == NULL)
		return -1;
	return ben_list_append(list, bs);
}

int ben_list_append_int(struct bencode *list, long long ll)
{
	struct bencode *bll = ben_int(ll);
	if (bll == NULL)
		return -1;
	return ben_list_append(list, bll);
}

struct bencode *ben_list_pop(struct bencode *list, size_t pos)
{
	struct bencode_list *l = ben_list_cast(list);
	struct bencode *value;

	assert(pos < l->n);

	value = ben_list_get(list, pos);

	for (; (pos + 1) < l->n; pos++)
		l->values[pos] = l->values[pos + 1];

	l->values[l->n - 1] = NULL;
	l->n--;
	return value;
}

void ben_list_set(struct bencode *list, size_t i, struct bencode *b)
{
	struct bencode_list *l = ben_list_cast(list);
	if (i >= l->n)
		bendie("ben_list_set() out of bounds: %zu\n", i);

	ben_free(l->values[i]);
	assert(b != NULL);
	l->values[i] = b;
}

char *ben_print(const struct bencode *b)
{
	size_t size = get_printed_size(b);
	char *data = malloc(size + 1);
	size_t len = 0;
	if (data == NULL) {
		benwarn("No memory to print\n");
		return NULL;
	}
	if (print(data, size, &len, b)) {
		free(data);
		return NULL;
	}
	assert(len == size);
	data[size] = 0;
	return data;
}

struct bencode *ben_str(const char *s)
{
	return ben_blob(s, strlen(s));
}

const char *ben_strerror(int error)
{
	switch (error) {
	case BEN_OK:
		return "OK (no error)";
	case BEN_INVALID:
		return "Invalid data";
	case BEN_INSUFFICIENT:
		return "Insufficient amount of data (need more data)";
	case BEN_NO_MEMORY:
		return "Out of memory";
	default:
		fprintf(stderr, "Unknown error code: %d\n", error);
		return NULL;
	}
}
