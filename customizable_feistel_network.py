# -*- coding: utf-8 -*-
"""
Created on Fri Jul  2 00:09:22 2021

@author: Ctariy
"""

import re


class Feistel(object):
    """Customizable Feistel Network."""

    def __init__(self, encryption_keys, block_size, function,
                 rounds_num, coding_dict):
        """
        Parameters
        ----------
        encryption_keys : keys are selected depending on the
            encryption/decryption algorithm.
        block_size: the size of the input blocks in this algorithm.
        function : s-box or p-box func(subblock, round_key).
        rounds_num : the number of rounds (stages) in the
            selected encryption algorithm.
        coding_dict : to set the encoding

        Returns
        -------
        Feistel network object.

        """
        self.encryption_keys = encryption_keys
        self.block_size = block_size
        self.coding = coding_dict
        self.coding_bits = len(list(coding_dict.values())[0])
        self.function = function
        self.rounds_num = rounds_num
        self.coding_inv = {v: k for k, v in coding_dict.items()}

    def encrypt(self, string):
        """Return the encrypted message."""
        string = self._encode(string)
        string = self._resize(string, self.block_size)

        subblock_len, subblocks = self._generate_subblocks(string)

        for i, subblock in enumerate(subblocks):
            for j in range(self.rounds_num):
                subblock[0] = self.function(subblock[0],
                                            self.encryption_keys[j],
                                            subblock_len)
                subblock[0], subblock[1] = subblock[1], subblock[0] ^ subblock[1] 
            subblocks[i] = subblock

        encrypted_string = self._get_string(subblocks, subblock_len)
        encrypted_string = self._resize(encrypted_string, self.coding_bits)

        return self._decode(encrypted_string)

    def decrypt(self, string):
        """Return the decrypted message."""
        string = self._encode(string)
        string = self._reresize(string)

        subblock_len, subblocks = self._generate_subblocks(string)

        for i, subblock in enumerate(subblocks):
            for j in range(self.rounds_num):
                sum_ = self.function(subblock[0] ^ subblock[1],
                                     -self.encryption_keys[::-1][j],
                                     subblock_len)
                subblock[0], subblock[1] = sum_, subblock[0]
            subblocks[i] = subblock

        decrypted_string = self._get_string(subblocks, subblock_len)
        decrypted_string = self._reresize(decrypted_string)

        return self._decode(decrypted_string)

    def _generate_subblocks(self, string):
        """Get subblocks from the string."""
        blocks = self._create_blocks(string, self.block_size)
        subblocks = [self._create_subblock(x) for x in blocks]
        subblock_len = len(subblocks[0][0])
        subblocks = [[int(y, 2) for y in x] for x in subblocks]
        return subblock_len, subblocks

    def _get_string(self, subblocks, subblock_len):
        """Assemble the string from subblocks."""
        string = ''
        for subblock in subblocks:
            s1 = '%0*d' % (subblock_len, int(bin(subblock[1])[2:]))
            s2 = '%0*d' % (subblock_len, int(bin(subblock[0])[2:]))
            string += s2 + s1
        return string

    def _resize(self, string, size):
        """Fit the message to the block size."""
        if len(string) % size != 0:
            string += '1'
        while len(string) % size != 0:
            string += '0'
        return string

    def _reresize(self, string):
        """Removes the bits added to make the message fit the block size."""
        if len(string) % self.coding_bits != 0:
            string = string[::-1]
            while string[0] == '0':
                string = string[1:]
            return string[1:][::-1]
        else:
            return string

    def _encode(self, string):
        """Encode the message according to the dictionary."""
        encoded_string = ''
        for letter in string:
            encoded_string += test_dict[letter]
        return encoded_string

    def _decode(self, string):
        """Decode the message according to the dictionary."""
        decoded_string = ''
        data = re.findall('.{%s}' % self.coding_bits, string)
        for letter in data:
            decoded_string += self.coding_inv[letter]
        return decoded_string

    def _create_blocks(self, string, size):
        """Split the string into blocks of equal length."""
        data = re.findall('.{%s}' % size, string)
        return data

    def _create_subblock(self, string):
        """Split the string into equal left and right subblocks."""
        return self._create_blocks(string, self.block_size // 2)


# TESTING #

def shift_function(subblock, shift, subblock_len):
    """Example of p-box - cyclic shift with key."""
    subblock = bin(subblock)[2:]
    subblock = '%0*d' % (subblock_len, int(subblock))
    return int(subblock[shift:] + subblock[:shift], 2)


test_dict = {  # Example of encoding - telegraphic alphabet (Baudot code)
    '1': '00000', 'E': '00001', "'": '00010', 'A': '00011', ' ': '00100',
    'S': '00101', 'I': '00110', 'U': '00111', ',': '01000', 'D': '01001',
    'R': '01010', 'J': '01011', 'N': '01100', 'F': '01101', 'C': '01110',
    'K': '01111', 'T': '10000', 'Z': '10001', 'L': '10010', 'W': '10011',
    'H': '10100', 'Y': '10101', 'P': '10110', 'Q': '10111', 'O': '11000',
    'B': '11001', 'G': '11010', '.': '11011', 'M': '11100', 'X': '11101',
    'V': '11110', '2': '11111'}

block_size = 64  # Size of blocks to be encrypted, in bits
rounds_num = 32  # Number of rounds of the Feistel network
encryption_keys = [i for i in range(1, rounds_num + 1)]  # Generate your keys

MESSAGE = "I work harder than God. If He had hired me, \
He would have made the world by Thursday. 'Keeping the Faith'".upper()

# USING #

feistel = Feistel(encryption_keys, block_size, shift_function,
                  rounds_num, test_dict)

print(f"""
Encryption by configurable Feistel's network.

Message for encryption:
{MESSAGE}

Ciphertext: {feistel.encrypt(MESSAGE)}

Decoding result:
{feistel.decrypt(feistel.encrypt(MESSAGE))}""")
