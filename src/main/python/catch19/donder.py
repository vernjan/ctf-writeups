#!/usr/bin/env python

'''
Santa has caught up with the information age and does not trust
clear-text commands anymore.
He has decided that all communications
have to be encrypted to prevent an unfriendly take-over of his team.
Santa chooses a simple, secure, and toolless encryption scheme.
However, his team's memory capacity is limited and so he can only use
their names (Dasher, Dancer, Prancer, Vixen, Comet, Cupid, Donder and
Blitzen) as keys.
Where is the team headed to?
'''

# keys = [ 'Dasher', 'Dancer', 'Prancer', 'Vixen', 'Comet', 'Cupid', 'Donder', 'Blitzen' ]
import codecs

#keys = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
keys = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j']
ciphertext = '463216327617246f67406f1266075ec622606c6671765537066636596e621e64e622c2b006066961c66e621f067676e77c6e665167a462c4b50477433617754222d7043542885747df6dd575970417d435223000'

from pycipher import ColTrans
import itertools


def attempt(k, ct, chain=''):
    result = ColTrans(k).decipher(ct)
    resultD = result \
        .replace('G', '0') \
        .replace('H', '1') \
        .replace('I', '2') \
        .replace('J', '3') \
        .replace('K', '4') \
        .replace('L', '5') \
        .replace('M', '6') \
        .replace('N', '7') \
        .replace('O', '8') \
        .replace('P', '9')
    if '464C4147' in resultD or '666C6167' in resultD:
        print('{}: {}'.format(chain, resultD))
        resultDASCII = codecs.decode(resultD, "hex")
        print(resultDASCII)
    return result


for combos in itertools.permutations(keys, 9):
    result = ciphertext \
        .replace('0', 'g') \
        .replace('1', 'h') \
        .replace('2', 'i') \
        .replace('3', 'j') \
        .replace('4', 'k') \
        .replace('5', 'l') \
        .replace('6', 'm') \
        .replace('7', 'n') \
        .replace('8', 'o') \
        .replace('9', 'p')
    current = ''
    #for key in combos:
    key = ''.join(combos)
    current += ' ' + key
    result = attempt(key, result, current)
