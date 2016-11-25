import binascii

ENGLISH_DIGRAMS = 'er in ti on te al an at ic en is re ra le ri ro st ne ar'.split(' ')


def single_byte_xor(var, key):
    return var ^ key


def bruteforce_key(encrypted_text):
    highest_digram_count = 0
    best_match = None
    best_key = None

    # Can be 0x00 to 0xff
    for key in xrange(255):
        
        decrypted = ''
        digram_count = 0

        for char in encrypted_text:
            decrypted_byte = chr(single_byte_xor(ord(char), key))
            decrypted += decrypted_byte

        decrypted_lower = decrypted.lower()

        for digram in ENGLISH_DIGRAMS:
            if digram in decrypted_lower:
                digram_count += 1

        if digram_count >= highest_digram_count:
            highest_digram_count = digram_count
            best_match = decrypted
            best_key = key

    return best_match, highest_digram_count, best_key


if __name__ == '__main__':
    best_matches = []
    best_keys = []
    highest_digram_count = 0

    for encrypted_text in file('data.txt'):
        encrypted_text = encrypted_text.strip()
        if not encrypted_text:
            continue

        encrypted_text = binascii.unhexlify(encrypted_text)

        i_best_match, i_highest_digram_count, i_key = bruteforce_key(encrypted_text)

        if i_highest_digram_count == highest_digram_count:
            best_matches.append(i_best_match)
            best_keys.append(i_key)

        if i_highest_digram_count > highest_digram_count:
            highest_digram_count = i_highest_digram_count
            best_matches = [i_best_match,]
            best_keys = [i_key,]
            

    for i in xrange(len(best_matches)):
        args = (best_matches[i], highest_digram_count, best_keys[i])
        print('%r (%s digrams | key %0.2X)' % args)


