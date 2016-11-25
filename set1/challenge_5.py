import binascii
from itertools import cycle, izip

_input = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""

#_input = 'andres.riancho@gmail.com'

key = 'ICE'

expected_output = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226' \
                  '324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20' \
                  '283165286326302e27282f'


def repeating_key_xor(message, key):
    xor = ''.join(chr(ord(c)^ord(k)) for c,k in izip(message, cycle(key)))
    return binascii.hexlify(xor)

output = repeating_key_xor(_input, key)

assert output == expected_output, 'Unexpected result "%s"' % output
print(output)
