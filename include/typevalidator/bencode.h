#ifndef TYPEVALIDATOR_BENCODE_H
#define TYPEVALIDATOR_BENCODE_H

#include <stdio.h>

enum bencodetype {
	BENCODE_DICT,
	BENCODE_INT,
	BENCODE_LIST,
	BENCODE_STR,
};

struct bencode;

struct bencode_dict {
	size_t n;
	struct bencode **keys;
	struct bencode **values;
};

struct bencode_list {
	size_t n;
	struct bencode **values;
};

struct bencode_str {
	size_t len;
	char *s;
};

struct bencode {
	enum bencodetype type;
	union {
		struct bencode_dict d;
		long long ll;
		struct bencode_str s;
	};
};

#endif
