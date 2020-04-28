from Cryptodome.Hash import SHA1
from Cryptodome.Cipher import AES
import argparse
import json
import os

SALT = "jjo+Ffqil5bdpo5VG82kLj8Ng1sK7L/rCqFTa39Zkom2/baqf5j9HMmsuCr0ipjYsPrsaNIOESWy7bDDGYWx1eA=="
BLOCK_SIZE = 16
CRC32_SIZE = 4

ENCRYPT_OPTION = "encrypt"
DECRYPT_OPTION = "decrypt"


class CRC32:
    def __init__(self):
        self.__table = self.__make_table()

    def compute(self, data):
        num = 0xD6EAF23C
        for idx in range(len(data)):
            num = num >> 8 ^ self.__table[data[idx] ^ num & 0xFF]
        return num

    @staticmethod
    def __make_table():
        table = []
        for idx1 in range(256):
            num = idx1
            for idx2 in range(8):
                num = num >> 1 if (num & 1) != 1 else num ^ 0x58E6D9AF
            table.append(num)
        return table


def check_steam_id(str):
    return str.isdigit()


# Based on function found at
# https://sysopfb.github.io/malware,/reverse-engineering/2018/05/12/MS-Derivation-functions.html
def password_derive_bytes(pstring, salt, iterations, keylen):
    lasthash = pstring + salt
    for i in range(iterations - 1):
        lasthash = SHA1.new(lasthash).digest()
    bytes = SHA1.new(lasthash).digest()
    ctrl = 1
    while len(bytes) < keylen:
        bytes += SHA1.new(str(ctrl).encode() + lasthash).digest()
        ctrl += 1
    return bytes[:keylen]


def pkcs5_unpad(data):
    return data[0:-data[-1]]


def pkcs5_pad(data):
    length = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([length] * length)


def decrypt_oc2(save_file_path, dest_file_path, steam_id):
    with open(save_file_path, 'rb') as file_d:
        data = file_d.read()
    if len(data) <= BLOCK_SIZE + CRC32_SIZE:
        raise RuntimeError("Cannot decrypt save because source save is too small")
    if not verify_crc32(data):
        print("WARNING: The save file seems corrupted (CRC32 mismatch)")
    aes_iv = data[:BLOCK_SIZE]
    data = data[BLOCK_SIZE:len(data) - CRC32_SIZE]
    key = password_derive_bytes(steam_id.encode(), SALT.encode(), 2, 32)
    cipher = AES.new(key, AES.MODE_CBC, iv=aes_iv)
    decrypted_file = pkcs5_unpad(cipher.decrypt(data))
    try:
        json.loads(decrypted_file)
    except json.JSONDecodeError:
        raise RuntimeError("Decryption failed, either the savegame is not valid or the wrong SteamID64 has been used.")
    with open(dest_file_path, "wb+") as file_d:
        file_d.write(decrypted_file)


def encrypt_oc2(save_file_path, dest_file_path, steam_id):
    with open(save_file_path, 'rb') as file_d:
        data = file_d.read()
    try:
        json.loads(data)
    except json.JSONDecodeError:
        raise RuntimeError("Cannot encrypt save because source save is not a valid JSON")
    key = password_derive_bytes(steam_id.encode(), SALT.encode(), 2, 32)
    cipher = AES.new(key, AES.MODE_CBC)
    aes_iv = cipher.iv
    with open(dest_file_path, "wb+") as file_d:
        crypted_data_with_iv = aes_iv + cipher.encrypt(pkcs5_pad(data))
        data_crc32 = CRC32().compute(crypted_data_with_iv)
        file_d.write(crypted_data_with_iv)
        file_d.write(data_crc32.to_bytes(4, byteorder='little'))


def verify_crc32(data):
    data_crc32 = CRC32().compute(data[0:len(data) - CRC32_SIZE])
    real_crc32 = int.from_bytes(data[len(data) - CRC32_SIZE:], byteorder='little')
    return data_crc32 == real_crc32


parser = argparse.ArgumentParser()
parser.add_argument("mode", type=str, choices=[ENCRYPT_OPTION, DECRYPT_OPTION])
parser.add_argument("source_save", type=str)
parser.add_argument("destination_save", type=str)
parser.add_argument("steam_id", type=str)
args = parser.parse_args()

# Prevent source and destination save from having to same path
if os.path.realpath(args.source_save) == os.path.realpath(args.destination_save):
    raise ValueError("Source save and destination save must be different")

if args.mode == DECRYPT_OPTION:
    decrypt_oc2(args.source_save, args.destination_save, args.steam_id)
else:
    encrypt_oc2(args.source_save, args.destination_save, args.steam_id)
