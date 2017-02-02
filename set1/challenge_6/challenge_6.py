import binascii
import hashlib
import base64
import string
import itertools

from itertools import cycle, izip, imap

MIN_KEYSIZE = 2
MAX_KEYSIZE = 40
ENGLISH_DIGRAMS = 'er in ti on te al an at ic en is re ra le ri ro st ne ar'.split(' ')

FREQ = {'a': 834, 'b': 154, 'c': 273, 'd': 414, 'e': 1260, 'f': 203,
        'g': 192, 'h': 611, 'i': 671, 'j': 23, 'k': 87, 'l': 424,
        'm': 253, 'n': 680, 'o': 770, 'p': 166, 'q': 9, 'r': 568,
        's': 611, 't': 937, 'u': 285, 'v': 106, 'w': 234, 'x': 20,
        'y': 204, 'z': 6, ' ': 2320}

# It's been base64'd after being encrypted with repeating-key XOR.
encoded_encrypted_data = file('6.txt').read()
encrypted_data = base64.b64decode(encoded_encrypted_data)

# Just for debugging
file('6.bin', 'w').write(encrypted_data)

s1 = bytearray(b'this is a test')
s2 = bytearray(b'wokka wokka!!!')


def hamming_distance_bin(x, y):
    return sum([bin(x[i] ^ y[i]).count('1') for i in range(len(x))])

assert hamming_distance_bin(s1, s2) == 37, 'Bad Hamming distance implementation'


def hamming_distance_bin_normalized(x, y):
    assert len(x) == len(y)
    return hamming_distance_bin(x, y) / float(len(x))


def calculate_normalized_distance_multi(string_list):
    """
    Calculates the normalized distance between multiple strings.
    Calculates all the distances between all the combinations and
    then divides them by the length.

    :param string_list: List of strings
    :return: The distance
    """
    dist = 0.0

    for i in xrange(len(string_list) - 1):
        dist += hamming_distance_bin_normalized(string_list[i],
                                                string_list[i+1])

    return dist / len(string_list)

# For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes,
# and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
normalized_distances = []

for key_size in xrange(MIN_KEYSIZE, MAX_KEYSIZE):

    encrypted_data_blocks = []

    for block_to_analyze in xrange(len(encrypted_data) / key_size - 1):
        encrypted_data_block = encrypted_data[key_size * block_to_analyze:
                                              key_size * (block_to_analyze + 1)]

        encrypted_data_blocks.append(bytearray(encrypted_data_block))
        #print(binascii.hexlify(encrypted_data_block))

    normalized_distance = calculate_normalized_distance_multi(encrypted_data_blocks)
    normalized_distances.append((key_size, normalized_distance))


# The KEYSIZE with the smallest normalized edit distance is probably the key.
# You could proceed perhaps with the smallest 2-3 KEYSIZE values.
# Or take 4 KEYSIZE blocks instead of 2 and average the distances.
def sort_by_normalized_distance(x, y):
    return cmp(x[1], y[1])

normalized_distances.sort(sort_by_normalized_distance)

potential_key_sizes = [normalized_distances[0][0],
                       normalized_distances[1][0],
                       normalized_distances[2][0]]

# Debug
print('The potential key sizes are:')
for potential_key_size, normalized_distance in normalized_distances[:3]:
    print(' - %s (distance: %s)' % (potential_key_size, normalized_distance))


def single_byte_xor(var, key):
    return var ^ key


def char_frequency_score(_input):
    _input = _input.lower()

    ret = 0

    for c in _input.lower():
        if c in FREQ:
            ret += FREQ[c]

    return ret


def bruteforce_key(encrypted_text):
    #print('Single byte brute forcing message with md5 hash: %s' % hashlib.md5(encrypted_text).hexdigest())
    potential_results = []

    # Can be 0x00 to 0xff
    for single_xor_key in xrange(255):

        decrypted = ''
        char_count = 0

        for char in encrypted_text:
            decrypted_byte = chr(single_byte_xor(ord(char), single_xor_key))
            decrypted += decrypted_byte

        score = char_frequency_score(decrypted)
        potential_results.append((score, single_xor_key, decrypted))

    def sort_by_first_item(x, y):
        return cmp(y[0], x[0])

    potential_results.sort(sort_by_first_item)

    return potential_results


def repeating_key_xor(message, xor_key):
    xor = ''.join(chr(ord(c) ^ ord(k)) for c, k in izip(message, cycle(xor_key)))
    return xor

# Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
for potential_key_size in potential_key_sizes:
    print('Brute forcing for potential key size %s.' % potential_key_size)

    # Now transpose the blocks: make a block that is the first byte of every block,
    # and a block that is the second byte of every block, and so on.
    #
    # First we get the blocks to perform 1-byte xor brute force
    transposed_block_list = []

    for transposed_block_iter in xrange(potential_key_size):
        transposed_block = ''

        for i in xrange(len(encrypted_data) / potential_key_size):
            transposed_block += encrypted_data[i * potential_key_size + transposed_block_iter]

        transposed_block_list.append(transposed_block)
        # print(binascii.hexlify(transposed_block))

    print('Got %s transposed blocks to brute force with 1-byte xor' % len(transposed_block_list))

    #assert len(transposed_block_list), potential_key_size
    #assert sum([len(tb) for tb in transposed_block_list]) == len(encrypted_data)

    # Solve each block as if it was single-character XOR. You already have code to do this.
    # For each block, the single-byte XOR key that produces the best looking histogram is the
    # repeating-key XOR key byte for that block. Put them together and you have the key.
    key_best_guesses = []

    for key_byte, transposed_block in enumerate(transposed_block_list):
        potential_bruteforced_key_data = bruteforce_key(transposed_block)

        best_guesses = []
        best_guess_num = 1
        print('The top %s best guesses for key byte[%s] are:' % (best_guess_num, key_byte))
        for digram_count, pkey, decrypted in potential_bruteforced_key_data[:best_guess_num]:
            print(' - %s (%r) with %s printable chars' % (chr(pkey), pkey, digram_count))
            best_guesses.append(chr(pkey))

        key_best_guesses.append(best_guesses)

    # Since the bruteforcing process for 1-byte xor is not perfect we try the
    # product of all best guesses
    potential_keys = []
    for potential_key_combination in itertools.product(*key_best_guesses):
        key = ''.join(potential_key_combination)
        potential_keys.append(key)

    print('Potential keys:')
    for key in potential_keys:
        print(' - %s (%r)' % (key, key))

    key_digram_store = []

    for key in potential_keys:
        print('Decrypting message with %s' % key)
        decrypted = repeating_key_xor(encrypted_data, key)

        digram_count = 0
        for digram in ENGLISH_DIGRAMS:
            digram_count += decrypted.count(digram)

        print('Got %s digrams' % digram_count)
        key_digram_store.append((key, digram_count))

    def sort_by_highest_digram_count(x, y):
        return cmp(y[1], x[1])

    key_digram_store.sort(sort_by_highest_digram_count)

    print('The message is:')
    key = key_digram_store[0][0]
    print(repeating_key_xor(encrypted_data, key))
