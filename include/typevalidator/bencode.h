#ifndef TYPEVALIDATOR_BENCODE_H
#define TYPEVALIDATOR_BENCODE_H

#include <stdio.h>

enum {
	BENCODE_BOOL = 1,
	BENCODE_DICT,
	BENCODE_INT,
	BENCODE_LIST,
	BENCODE_STR,
};

struct bencode;

struct bencode_bool {
	char type;
	char b;
};

struct bencode_dict {
	char type;
	size_t n;
	size_t alloc;
	/* keys and values can be put into a same array, later */
	struct bencode **keys;
	struct bencode **values;
};

struct bencode_int {
	char type;
	long long ll;
};

struct bencode_list {
	char type;
	size_t n;
	size_t alloc;
	struct bencode **values;
};

struct bencode_str {
	char type;
	size_t len;
	char *s;
};

struct bencode {
	char type;
};

struct bencode *ben_decode(const void *data, size_t len);
struct bencode *ben_decode2(const void *data, size_t len, size_t *off);
void *ben_encode(size_t *len, const struct bencode *b);
void ben_free(struct bencode *b);

struct bencode *ben_blob(const void *data, size_t len);
struct bencode *ben_bool(int b);
struct bencode *ben_dict(void);
struct bencode *ben_int(long long ll);

struct bencode *ben_list(void);
int ben_list_append(struct bencode *list, struct bencode *b);
static struct bencode_list *ben_list_cast(struct bencode *list)
{
	return list->type == BENCODE_LIST ? ((struct bencode_list *) list) : NULL;
}

struct bencode *ben_str(const char *s);


#endif
