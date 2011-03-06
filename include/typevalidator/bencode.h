#ifndef TYPEVALIDATOR_BENCODE_H
#define TYPEVALIDATOR_BENCODE_H

#include <stdio.h>

enum bencodetype {
	BENCODE_BOOL = 1,
	BENCODE_DICT,
	BENCODE_INT,
	BENCODE_LIST,
	BENCODE_STR,
};

struct bencode;

struct bencode_dict {
	size_t n;
	size_t alloc;
	struct bencode **keys;
	struct bencode **values;
};

struct bencode_list {
	size_t n;
	size_t alloc;
	struct bencode **values;
};

struct bencode_str {
	size_t len;
	char *s;
};

struct bencode {
	enum bencodetype type;
	union {
		int b;                 /* bool */
		struct bencode_dict d; /* dict */
		long long ll;          /* int */
		struct bencode_list l; /* list */
		struct bencode_str s;  /* str */
	};
};

struct bencode *ben_decode(const void *data, size_t len);
struct bencode *ben_decode2(const void *data, size_t len, size_t *off);
void ben_free(struct bencode *b);

#endif
