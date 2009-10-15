# A simple type validator to check types of bdecoded data that comes from
# an untrusted source (say, network).
#
# This source module is in public domain. You may do whatever you want with it.
#
# Originally written by Heikki Orsila <heikki.orsila@iki.fi> on 2009-09-12

ANY = 'a'
BOOL = True
INT = 0
STRING = 'x'
FLOAT = 1.0
ZERO_OR_MORE = '*'
ONE_OR_MORE = '+'

class BOOL_KEY:
    key = None
class INT_KEY:
    key = None
class FLOAT_KEY:
    key = None
class OPTIONAL_KEY:
    def __init__(self, key):
        self.key = key
class STRING_KEY:
    key = None
keytypemap = {BOOL_KEY: type(BOOL),
              FLOAT_KEY: type(FLOAT),
              INT_KEY: type(INT),
              STRING_KEY: type(STRING),
             }

class Invalid_Format_Object(Exception):
    def __init__(self, reason=''):
        self.reason = reason

    def __str__(self):
        return self.reason

def validate_list(fmt, o):
    fmt = list(fmt)
    o = list(o)
    while len(fmt) > 0:
        fitem = fmt.pop(0)
        if fitem == ZERO_OR_MORE or fitem == ONE_OR_MORE:
            if len(fmt) == 0:
                raise Invalid_Format_Object()
            ftype = fmt.pop(0)
            if len(o) == 0:
                if len(fmt) > 0:
                    continue
                return fitem == ZERO_OR_MORE
            while len(o) > 0:
                if not validate(ftype, o[0]):
                    if len(fmt) > 0:
                        break
                    return False
                o.pop(0)
            continue
        if len(o) == 0:
            return False
        oitem = o.pop(0)
        if not validate(fitem, oitem):
            return False
    return len(o) == 0

def validate_dict(fmt, o):
    for key in fmt.keys():
        if o.has_key(key) and validate(fmt[key], o[key]):
            continue
        t = keytypemap.get(key)
        if t != None:
            # STRING_KEY, INT_KEY, ...
            for okey in o.keys():
                if type(okey) != t:
                    # Associate int with long
                    if t != int or type(okey) != long:
                        return False
                if validate(fmt[key], o[okey]) == False:
                    return False
        elif isinstance(key, OPTIONAL_KEY):
            # OPTIONAL_KEY
            if o.has_key(key.key) and validate(fmt[key], o[key.key]) == False:
                return False
        else:
            return False
    return True

def validate(fmt, o):
    if fmt == ANY:
        return True

    # Is this a user defined checker function?
    if callable(fmt):
        return fmt(o)

    if type(fmt) != type(o):
        # Associate int type with long. We don't use LONG as a validator
        # keyword, just INT
        if type(fmt) != int or type(o) != long:
            return False

    if type(fmt) == list:
        return validate_list(fmt, o)
    elif type(fmt) == dict:
        return validate_dict(fmt, o)
    return True

def test_validate():
    assert(validate([STRING, [ONE_OR_MORE, INT], [ZERO_OR_MORE, INT], {'a': INT, 1: STRING}], ['fff', [0], [], {'a': 0, 1: 'foo'}]))
    assert(validate([STRING, [ONE_OR_MORE, INT], [ZERO_OR_MORE, INT], {'a': INT, 1: STRING}], [1, [0], [], {'a': 0, 1: 'foo'}]) == False)
    assert(validate([STRING, [ONE_OR_MORE, INT], [ZERO_OR_MORE, INT], {'a': INT, 1: STRING}], ['fff', [], [], {'a': 0, 1: 'foo'}]) == False)
    assert(validate([ONE_OR_MORE, INT, ZERO_OR_MORE, STRING], [1, 1, 1]))
    assert(validate([ONE_OR_MORE, INT, ZERO_OR_MORE, STRING], [1, 1, 1, 's']))
    assert(validate([ZERO_OR_MORE, INT, ONE_OR_MORE, STRING], [1, 1, 1, 's']))
    assert(validate([ZERO_OR_MORE, INT, ONE_OR_MORE, STRING], [1, 1, 1]) == False)
    assert(validate([ZERO_OR_MORE, INT, ONE_OR_MORE, STRING], ['d']))
    assert(validate([ZERO_OR_MORE, INT, ONE_OR_MORE, STRING], []) == False)

    assert(validate(lambda x: x % 2 == 0, 0))
    assert(validate(lambda x: x % 2 == 0, 1) == False)

    assert(validate({STRING_KEY: STRING}, {'a': 'b'}))
    assert(validate({STRING_KEY: STRING}, {1: 'b'}) == False)
    assert(validate({STRING_KEY: STRING}, {'a': 1}) == False)
    assert(validate({STRING_KEY: INT}, {'a': 1}))
    assert(validate({INT_KEY: STRING}, {1: 'a'}))
    assert(validate({INT_KEY: STRING}, {1: 'a', 'b': 2}) == False)

    # Extra keys in dictionary are allowed
    assert(validate({'x': INT}, {'x': 1, 'y': 1}))
    # Missing key fails
    assert(validate({'x': INT}, {'y': 1}) == False)

    # OK
    assert(validate({'x': INT, STRING_KEY: INT}, {'x': 1, 'y': 1}))
    # Non-string key
    assert(validate({'x': INT, STRING_KEY: INT}, {'x': 1, 1: 1}) == False)
    # Missing key, but correct key type
    assert(validate({'x': INT, STRING_KEY: INT}, {'y': 1}) == False)

    assert(validate({'x': BOOL}, {'x': False}))
    assert(validate({'x': BOOL}, {'x': 0}) == False)

    # Test OPTIONAL_KEY
    assert(validate({OPTIONAL_KEY('x'): INT}, {}))
    assert(validate({OPTIONAL_KEY('x'): INT}, {'x': 1}))
    assert(validate({OPTIONAL_KEY('x'): INT}, {'x': 'invalid'}) == False)

    # Test that int and long are equivalent
    assert(validate({'x': INT}, {'x': 0L}))
    assert(validate({INT_KEY: ANY}, {0L: 'x'}))

if __name__ == '__main__':
    test_validate()
