# Written by Petru Paler and Ross Cohen
# see LICENSE.bencode for license information
#
# Changes:
#
# 2009-09-25: Support bool type (Heikki Orsila <heikki.orsila@iki.fi>)
#             and type validator. No copyrights claimed for this extension.
#
#             Example:
#
#             dictionary = fmt_bdecode({'name': STRING, 'age': INT}, data)

from types import BooleanType, IntType, LongType, StringType, ListType, TupleType, DictType
from typevalidator import validate

def decode_bool(x, f):
    if x[f + 1] == '0':
        return (False, f + 2)
    elif x[f + 1] == '1':
        return (True, f + 2)
    raise ValueError

def decode_int(x, f):
    f = f+1
    newf = x.index('e', f)
    if x[f] != '-' and x[f].isdigit() == False:
        raise ValueError
    try:
        n = int(x[f:newf])
    except (OverflowError, ValueError):
        n = long(x[f:newf])
    if x[f] == '-':
        if x[f + 1] == '0':
            raise ValueError
    elif x[f] == '0' and newf != f+1:
        raise ValueError
    return (n, newf+1)

def decode_string(x, f):
    colon = x.index(':', f)
    try:
        n = int(x[f:colon])
    except (OverflowError, ValueError):
        n = long(x[f:colon])
    if x[f] == '0' and colon != f+1:
        raise ValueError
    colon += 1
    return (x[colon:colon+n], colon+n)

def decode_list(x, f):
    r, f = [], f+1
    while x[f] != 'e':
        v, f = decode_func[x[f]](x, f)
        r.append(v)
    return (r, f + 1)

def decode_dict(x, f):
    r, f = {}, f+1
    lastkey = None
    while x[f] != 'e':
        try:
            k, f = decode_string(x, f)
        except ValueError:
            k, f = decode_int(x, f)
        if lastkey >= k:
            raise ValueError
        lastkey = k
        r[k], f = decode_func[x[f]](x, f)
    return (r, f + 1)

decode_func = {}
decode_func['b'] = decode_bool
decode_func['l'] = decode_list
decode_func['d'] = decode_dict
decode_func['i'] = decode_int
decode_func['0'] = decode_string
decode_func['1'] = decode_string
decode_func['2'] = decode_string
decode_func['3'] = decode_string
decode_func['4'] = decode_string
decode_func['5'] = decode_string
decode_func['6'] = decode_string
decode_func['7'] = decode_string
decode_func['8'] = decode_string
decode_func['9'] = decode_string

def bdecode(x):
    try:
        r, l = decode_func[x[0]](x, 0)
    except (IndexError, KeyError):
        raise ValueError
    if l != len(x):
        raise ValueError
    return r

def test_bdecode():
    try:
        bdecode('0:0:')
        assert 0
    except ValueError:
        pass
    try:
        bdecode('ie')
        assert 0
    except ValueError:
        pass
    try:
        bdecode('i341foo382e')
        assert 0
    except ValueError:
        pass
    assert bdecode('i4e') == 4L
    assert bdecode('i0e') == 0L
    assert bdecode('i123456789e') == 123456789L
    assert bdecode('i-10e') == -10L
    try:
        bdecode('i-0e')
        assert 0
    except ValueError:
        pass
    try:
        bdecode('i 2e')
        assert 0
    except ValueError:
        pass
    try:
        bdecode('i123')
        assert 0
    except ValueError:
        pass
    try:
        bdecode('')
        assert 0
    except ValueError:
        pass
    try:
        bdecode('i6easd')
        assert 0
    except ValueError:
        pass
    try:
        bdecode('35208734823ljdahflajhdf')
        assert 0
    except ValueError:
        pass
    try:
        bdecode('2:abfdjslhfld')
        assert 0
    except ValueError:
        pass
    assert bdecode('0:') == ''
    assert bdecode('3:abc') == 'abc'
    assert bdecode('10:1234567890') == '1234567890'
    try:
        bdecode('02:xy')
        assert 0
    except ValueError:
        pass
    try:
        bdecode('l')
        assert 0
    except ValueError:
        pass
    assert bdecode('le') == []
    try:
        bdecode('leanfdldjfh')
        assert 0
    except ValueError:
        pass
    assert bdecode('l0:0:0:e') == ['', '', '']
    try:
        bdecode('relwjhrlewjh')
        assert 0
    except ValueError:
        pass
    assert bdecode('li1ei2ei3ee') == [1, 2, 3]
    assert bdecode('l3:asd2:xye') == ['asd', 'xy']
    assert bdecode('ll5:Alice3:Bobeli2ei3eee') == [['Alice', 'Bob'], [2, 3]]
    try:
        bdecode('d')
        assert 0
    except ValueError:
        pass
    try:
        bdecode('defoobar')
        assert 0
    except ValueError:
        pass
    assert bdecode('de') == {}
    assert bdecode('d3:agei25e4:eyes4:bluee') == {'age': 25, 'eyes': 'blue'}
    assert bdecode('d8:spam.mp3d6:author5:Alice6:lengthi100000eee') == {'spam.mp3': {'author': 'Alice', 'length': 100000}}
    try:
        bdecode('d3:fooe')
        assert 0
    except ValueError:
        pass
    try:
        bdecode('di1e0:e')
    except ValueError:
        pass
    try:
        bdecode('d1:b0:1:a0:e')
        assert 0
    except ValueError:
        pass
    try:
        bdecode('d1:a0:1:a0:e')
        assert 0
    except ValueError:
        pass
    try:
        bdecode('i03e')
        assert 0
    except ValueError:
        pass
    try:
        bdecode('l01:ae')
        assert 0
    except ValueError:
        pass
    try:
        bdecode('9999:x')
        assert 0
    except ValueError:
        pass
    try:
        bdecode('l0:')
        assert 0
    except ValueError:
        pass
    try:
        bdecode('d0:0:')
        assert 0
    except ValueError:
        pass
    try:
        bdecode('d0:')
        assert 0
    except ValueError:
        pass
    try:
        bdecode('00:')
        assert 0
    except ValueError:
        pass
    try:
        bdecode('l-3:e')
        assert 0
    except ValueError:
        pass
    try:
        bdecode('i-03e')
        assert 0
    except ValueError:
        pass
    try:
        bdecode('b2')
        assert 0
    except ValueError:
        pass

def fmt_bdecode(fmt, data):
    try:
        x = bdecode(data)
    except ValueError:
        return None
    if not validate(fmt, x):
        return None
    return x

class Bencached(object):
    __slots__ = ['bencoded']

    def __init__(self, s):
        self.bencoded = s

def bencode_bool(x, b):
    b.extend(('b', str(int(x))))

def bencode_int(x, b):
    b.extend(('i', str(x), 'e'))

def bencode_string(x, b):
    b.extend((str(len(x)), ':', x))

def bencode_list(x, b):
    b.append('l')
    for e in x:
        encode_func[type(e)](e, b)
    b.append('e')

def bencode_dict(x, b):
    b.append('d')
    klist = x.keys()
    klist.sort()
    for k in klist:
        if type(k) is StringType:
            bencode_string(k, b)
        elif type(k) is IntType or type(k) is LongType:
            bencode_int(k, b)
        else:
            assert False
        encode_func[type(x[k])](x[k], b)
    b.append('e')

def bencode_cached(x, b):
    b.append(x.bencoded)

encode_func = {}
encode_func[BooleanType] = bencode_bool
encode_func[IntType] = bencode_int
encode_func[LongType] = bencode_int
encode_func[StringType] = bencode_string
encode_func[ListType] = bencode_list
encode_func[TupleType] = bencode_list
encode_func[DictType] = bencode_dict
encode_func[Bencached] = bencode_cached

def bencode(item):
    b = []
    try:
        encode_func[type(item)](item, b)
    except KeyError:
        raise ValueError
    return ''.join(b)

def test_bencode():
    assert bencode(4) == 'i4e'
    assert bencode(0) == 'i0e'
    assert bencode(-10) == 'i-10e'
    assert bencode(12345678901234567890L) == 'i12345678901234567890e'
    assert bencode('') == '0:'
    assert bencode('abc') == '3:abc'
    assert bencode('1234567890') == '10:1234567890'
    assert bencode([]) == 'le'
    assert bencode([1, 2, 3]) == 'li1ei2ei3ee'
    assert bencode([['Alice', 'Bob'], [2, 3]]) == 'll5:Alice3:Bobeli2ei3eee'
    assert bencode({}) == 'de'
    assert bencode({'age': 25, 'eyes': 'blue'}) == 'd3:agei25e4:eyes4:bluee'
    assert bencode({'spam.mp3': {'author': 'Alice', 'length': 100000}}) == 'd8:spam.mp3d6:author5:Alice6:lengthi100000eee'
    assert bencode(False) == 'b0'
    assert bencode(True) == 'b1'
    assert bencode([True, 2]) == 'lb1i2ee'
    assert bencode([2, False]) == 'li2eb0e'
    assert bencode({1: 'foo'}) == 'di1e3:fooe'

if __name__ == '__main__':
    test_bdecode()
    test_bencode()
