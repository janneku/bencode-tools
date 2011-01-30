# type validator documentation as a commented source code :-)

from bencode.py import fmt_bdecode
from typevalidator import validate, ANY, ZERO_OR_MORE, ONE_OR_MORE, OPTIONAL_KEY

# Syntax of validate: validate(specification, object)
# Syntax of fmt_bdecode: fmt_bdecode(specification, blob)
#
# Blob is first transformed to an object with bdecode, then validated with
# type validator. This can be done with one call with fmt_bdecode()

# Asserted examples with type validator:

# Demand a dictionary whose keys and values are strings:
assert validate({str: str}, {'name': 'Cheradenine'})
assert validate({str: str}, {1: 'Cheradenine'}) == False
assert validate({str: str}, {'name': 1}) == False

# Demand a dictionary whose keys are integers but values may have any
# (supported) type. Furthermore, key with value 123 must exist.
assert validate({int: ANY, 123: ANY}, {123: 'x'})
assert validate({int: ANY, 123: ANY}, {123: 456})
assert validate({int: ANY, 123: ANY}, {4: 'x'}) == False # 123 does not exist

# List may begin with ZERO_OR_MORE or ONE_OR_MORE to specify that minimum
# length of the list is either zero or one, respectively. If either is
# used, then also a type must be specified after this.
assert validate([ZERO_OR_MORE, ANY], [])
assert validate([ONE_OR_MORE, ANY], ['x'])
assert validate([ONE_OR_MORE, ANY], []) == False
assert validate([ONE_OR_MORE, str], ['x', 1]) == False

# Recursive data structures are easy to specify! Define a list of
# dictionaries.
assert validate([ZERO_OR_MORE, {'name': str}], [{'name': 'User1'}, {'name': 'User2'}])
assert validate([ZERO_OR_MORE, {'name': str}], [1, {'name': 'User1'}]) == False

# Define a list that contains one string and one dictionary:
assert validate([str, {}], ['foo', {}])
assert validate([str, {}], [1, {}]) == False
assert validate([str, {}], ['foo', 1]) == False
assert validate([str, {}], ['foo', {}, 3]) == False # Too long a list

# Extra keys are allowed in the dictionary. Even if only 'x' key is specified,
# other keys are allowed. This was a choice to make message protocols
# extensible.
assert validate({'age': int}, {'age': 1, 'other': 'stuff'})

# Require positive integers by using lambdas
assert validate({'x': lambda x: type(x) == int and x > 0}, {'x': -1}) == False

# bencode example

blob = read_from_socket()
if blob == None:
    return
specification = {'name': str,
                 OPTIONAL_KEY('email'): str,
                 OPTIONAL_KEY('age'): int,
                 'a-list': [],
                 'non-empty-string-list': [ONE_OR_MORE, str],
                }
msg = fmt_bdecode(specification, blob)
if msg == None:
    # Invalid object
    return

# Now it is guaranteed that msg is a dictionary with previous specification.
# msg['name'] exists, msg['email'] and msg['age'] may exist.
# If msg['email'] exists, it is a string. If msg['age'] exists, it is an
# integer. 'a-list' exists and it is
# a list, but nothing is specified about type inside the list.
# msg['non-empty-string-list'] exists, and it is a non-empty list that
# contains strings.
