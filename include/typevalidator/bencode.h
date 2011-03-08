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
size_t ben_encoded_size(const struct bencode *b);
void *ben_encode(size_t *len, const struct bencode *b);
void ben_free(struct bencode *b);

struct bencode *ben_blob(const void *data, size_t len);
struct bencode *ben_bool(int b);
struct bencode *ben_dict(void);
struct bencode *ben_int(long long ll);
struct bencode *ben_list(void);
int ben_list_append(struct bencode *list, struct bencode *b);
struct bencode *ben_str(const char *s);

static inline const struct bencode_bool *ben_bool_const_cast(const struct bencode *b)
{
	return b->type == BENCODE_BOOL ? ((const struct bencode_bool *) b) : NULL;
}
static inline struct bencode_bool *ben_bool_cast(struct bencode *b)
{
	return b->type == BENCODE_BOOL ? ((struct bencode_bool *) b) : NULL;
}

static inline const struct bencode_dict *ben_dict_const_cast(const struct bencode *b)
{
	return b->type == BENCODE_DICT ? ((const struct bencode_dict *) b) : NULL;
}
static inline struct bencode_dict *ben_dict_cast(struct bencode *b)
{
	return b->type == BENCODE_DICT ? ((struct bencode_dict *) b) : NULL;
}

static inline const struct bencode_int *ben_int_const_cast(const struct bencode *i)
{
	return i->type == BENCODE_INT ? ((const struct bencode_int *) i) : NULL;
}
static inline struct bencode_int *ben_int_cast(struct bencode *i)
{
	return i->type == BENCODE_INT ? ((struct bencode_int *) i) : NULL;
}

static inline const struct bencode_list *ben_list_const_cast(const struct bencode *list)
{
	return list->type == BENCODE_LIST ? ((const struct bencode_list *) list) : NULL;
}
static inline struct bencode_list *ben_list_cast(struct bencode *list)
{
	return list->type == BENCODE_LIST ? ((struct bencode_list *) list) : NULL;
}

static inline const struct bencode_str *ben_str_const_cast(const struct bencode *str)
{
	return str->type == BENCODE_STR ? ((const struct bencode_str *) str) : NULL;
}
static inline struct bencode_str *ben_str_cast(struct bencode *str)
{
	return str->type == BENCODE_STR ? ((struct bencode_str *) str) : NULL;
}

#endif
