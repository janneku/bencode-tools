# A simple type validator to check types of bdecoded data that comes from
# an untrusted source (say, network).
#
# This source module is in public domain. You may do whatever you want with it.
#
# Originally written by Heikki Orsila <heikki.orsila@iki.fi> on 2009-09-12

from types import FunctionType

# BOOL*, INT*, STRING* and FLOAT* are used for backward compability
# with the old interface. New code should use bool/int/str/float directly.
BOOL = bool
BOOL_KEY = bool
INT = int
INT_KEY = int
STRING = str
STRING_KEY = str
FLOAT = float
FLOAT_KEY = float

class ANY:
    pass
class ZERO_OR_MORE:
    pass
class ONE_OR_MORE:
    pass

class OPTIONAL_KEY:
    def __init__(self, key):
        self.key = key

class Invalid_Format_Object(Exception):
    def __init__(self, reason=''):
        self.reason = reason

    def __str__(self):
        return self.reason

def validate_list(fmt, o):
    if type(o) != list:
        return False
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
    if type(o) != dict:
        return False
    for key in fmt.keys():
        if o.has_key(key) and validate(fmt[key], o[key]):
            continue
        if type(key) == type:
            # str, int, ...
            for okey in o.keys():
                if type(okey) != key:
                    # Associate int with long
                    if key != int or type(okey) != long:
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
    if type(fmt) == FunctionType:
        return fmt(o)
    elif type(fmt) == list:
        return validate_list(fmt, o)
    elif type(fmt) == dict:
        return validate_dict(fmt, o)
    elif type(fmt) == type:
        if fmt != type(o):
            # Associate int type with long. We don't use LONG as a validator
            # keyword, just int
            if fmt != int or type(o) != long:
                return False
    # If given format is a not a type but a value, compare input to the given value
    elif fmt != o:
        return False

    return True

def test_validate():
    assert(validate([str, [ONE_OR_MORE, int], [ZERO_OR_MORE, int], {'a': int, 1: str}], ['fff', [0], [], {'a': 0, 1: 'foo'}]))
    assert(validate([str, [ONE_OR_MORE, int], [ZERO_OR_MORE, int], {'a': int, 1: str}], [1, [0], [], {'a': 0, 1: 'foo'}]) == False)
    assert(validate([str, [ONE_OR_MORE, int], [ZERO_OR_MORE, int], {'a': int, 1: str}], ['fff', [], [], {'a': 0, 1: 'foo'}]) == False)
    assert(validate([ONE_OR_MORE, int, ZERO_OR_MORE, str], [1, 1, 1]))
    assert(validate([ONE_OR_MORE, int, ZERO_OR_MORE, str], [1, 1, 1, 's']))
    assert(validate([ZERO_OR_MORE, int, ONE_OR_MORE, str], [1, 1, 1, 's']))
    assert(validate([ZERO_OR_MORE, int, ONE_OR_MORE, str], [1, 1, 1]) == False)
    assert(validate([ZERO_OR_MORE, int, ONE_OR_MORE, str], ['d']))
    assert(validate([ZERO_OR_MORE, int, ONE_OR_MORE, str], []) == False)

    assert(validate(lambda x: x % 2 == 0, 0))
    assert(validate(lambda x: x % 2 == 0, 1) == False)

    assert(validate({str: str}, {'a': 'b'}))
    assert(validate({str: str}, {1: 'b'}) == False)
    assert(validate({str: str}, {'a': 1}) == False)
    assert(validate({str: int}, {'a': 1}))
    assert(validate({int: str}, {1: 'a'}))
    assert(validate({int: str}, {1: 'a', 'b': 2}) == False)

    # Extra keys in dictionary are allowed
    assert(validate({'x': int}, {'x': 1, 'y': 1}))
    # Missing key fails
    assert(validate({'x': int}, {'y': 1}) == False)

    # OK
    assert(validate({'x': int, str: int}, {'x': 1, 'y': 1}))
    # Non-string key
    assert(validate({'x': int, str: int}, {'x': 1, 1: 1}) == False)
    # Missing key, but correct key type
    assert(validate({'x': int, str: int}, {'y': 1}) == False)

    assert(validate({'x': bool}, {'x': False}))
    assert(validate({'x': bool}, {'x': 0}) == False)

    # Test OPTIONAL_KEY
    assert(validate({OPTIONAL_KEY('x'): int}, {}))
    assert(validate({OPTIONAL_KEY('x'): int}, {'x': 1}))
    assert(validate({OPTIONAL_KEY('x'): int}, {'x': 'invalid'}) == False)

    # Test that int and long are equivalent
    assert(validate({'x': int}, {'x': 0L}))
    assert(validate({int: ANY}, {0L: 'x'}))

    # Typevalidator can be used to check that values are equal
    assert(validate([1, 2, 3, [True, 'a']], [1, 2, 3, [True, 'a']]))
    assert(validate('foo', 'bar') == False)

def benchmark():
    specification = {'uid': str,
                     'ids': [ZERO_OR_MORE, int],
                     'purposes': [ZERO_OR_MORE, str],
                     'metas': [ZERO_OR_MORE, {}],
                    }
    request = {'uid': '0123456789abcdef',
               'ids': [0, 1, 2, 3, 4],
               'purposes': ['a', 'b', 'c', 'd', 'e'],
               'metas': [{}, {}, {}, {}, {}],
              }
    for i in xrange(100000):
        if not validate(specification, request):
            assert(False)

if __name__ == '__main__':
    test_validate()
