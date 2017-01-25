import binascii

# tip: english text
ENCRYPTED_TEXT = binascii.unhexlify('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
ENGLISH_DIGRAMS = 'er in ti on te al an at ic en is re ra le ri ro st ne ar'.split(' ')


def single_byte_xor(var, key):
    return var ^ key


def bruteforce_key():
    highest_digram_count = 0
    best_match = None

    # Can be 0x00 to 0xff
    for key in xrange(255):
        
        decrypted = ''
        digram_count = 0

        for char in ENCRYPTED_TEXT:
            decrypted_byte = chr(single_byte_xor(ord(char), key))
            decrypted += decrypted_byte

        decrypted_lower = decrypted.lower()

        for digram in ENGLISH_DIGRAMS:
            if digram in decrypted_lower:
                digram_count += 1

        if digram_count > highest_digram_count:
            highest_digram_count = digram_count
            best_match = decrypted

    print('%r (%s digrams)' % (best_match, highest_digram_count))


if __name__ == '__main__':
    bruteforce_key()
