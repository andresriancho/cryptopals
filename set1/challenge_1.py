import base64
import binascii

_input = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
output = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

transformed_output = binascii.unhexlify(_input)
transformed_output = base64.b64encode(transformed_output)

assert transformed_output == output, 'Unexpected result %s' % transformed_output
