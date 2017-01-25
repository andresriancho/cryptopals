import binascii

a = '1c0111001f010100061a024b53535009181c'
b = '686974207468652062756c6c277320657965'
expected_output = '746865206b696420646f6e277420706c6179'


def fixed_xor(var, key):
    assert len(var) == len(key), 'Lengths should be equal'

    var = binascii.unhexlify(var)
    key = binascii.unhexlify(key)

    xor = [chr(ord(a) ^ ord(b)) for (a, b) in zip(var, key)]
    xor = ''.join(xor)
    # print xor
    return binascii.hexlify(xor)

output = fixed_xor(a, b)

assert output == expected_output, 'Unexpected result "%s"' % output
