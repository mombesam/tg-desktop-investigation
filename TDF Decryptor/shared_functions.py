import hashlib
import tgcrypto
import os


#######################################
##### Shared decryption functions #####
#######################################


# Source: https://github.com/lilydjwg/telegram-cache-decryption
def sha1(data):
    m = hashlib.sha1()
    m.update(data)
    return m.digest()


# Source: https://github.com/lilydjwg/telegram-cache-decryption
def prepare_aes_oldmtp(key, msgKey):
    sha1_a = sha1(msgKey[:16] + key[8:8 + 32])

    sha1_b = sha1(
        key[8 + 32: 8 + 32 + 16]
        + msgKey[:16]
        + key[8 + 48: 8 + 48 + 16]
    )

    sha1_c = sha1(
        key[8 + 64: 8 + 64 + 32] + msgKey[:16])
    sha1_d = sha1(
        msgKey[:16] + key[8 + 96: 8 + 96 + 32])

    aesKey = sha1_a[:8] + sha1_b[8: 8 + 12] + sha1_c[4: 4 + 12]
    aesIv = sha1_a[8: 8 + 12] + sha1_b[:8] + sha1_c[16: 16 + 4] + sha1_d[:8]

    return aesKey, aesIv


# Source: https://github.com/lilydjwg/telegram-cache-decryption
def aes_decrypt_local(src, authkey, key128):
    aesKey, aesIV = prepare_aes_oldmtp(authkey, key128)
    dst = tgcrypto.ige256_decrypt(src, aesKey, aesIV)
    return bytearray(dst)


# Source: https://github.com/lilydjwg/telegram-cache-decryption
def decrypt_local(encrypted, key):
    encryptedKey = encrypted[:16]
    decrypted = aes_decrypt_local(
        encrypted[16:], key, encryptedKey)
    if sha1(decrypted)[:16] != encryptedKey:
        raise ValueError('bad checksum for decrypted data')

    dataLen = int.from_bytes(decrypted[:4], 'little')
    return decrypted[4:dataLen]


################################
##### Localkey generation #####
################################

# Sources: https://github.com/lilydjwg/telegram-cache-decryption, https://github.com/Py0zz1/TelegramDesktop_Decrypt
def create_base_key(salt, passcode):
	hashKey = hashlib.sha512(salt)
	hashKey.update(passcode)
	hashKey.update(salt)

	iterCount = 100000 if passcode else 1
	dst = hashlib.pbkdf2_hmac("sha512", hashKey.digest(), salt, iterCount, 256)

	print("\n##### Base key creation (key_datas) #####")
	print("[ALGORITHM] PKCS5_PBKDF2_HMAC_SHA512 (256B)")
	print(f"[BASE KEY] {dst.hex()}")

	return dst


# Sources: https://github.com/lilydjwg/telegram-cache-decryption, https://github.com/Py0zz1/TelegramDesktop_Decrypt
def generate_local_key(localkey_block, base_key):
    print("\n##### Local key generation #####")

    localkey_dec_key = localkey_block[:16]
    print(f"[DECRYPTION KEY] {localkey_dec_key.hex()}")

    decrypted_content = aes_decrypt_local(
        localkey_block[16:], base_key, localkey_block[:16])
    if sha1(decrypted_content)[:16] != localkey_block[:16]:
        raise ValueError('bad checksum for decrypted data (bad decryption key)')

    data_len = int.from_bytes(decrypted_content[:4], 'little')

    print(f"[LOCALKEY] {decrypted_content[4:data_len].hex()}")
    return decrypted_content[4:data_len]


############################################
##### key_datas parsing and decryption #####
############################################

# Source: https://github.com/lilydjwg/telegram-cache-decryption
def tdf_file_signature_check(filepath):
    with open(filepath, "rb") as file:
        if file.read(4) != b'TDF$':
            raise ValueError('wrong file type (TDF$ header not found)')

        version = file.read(4)
        data = file.read()

    m = hashlib.md5()
    m.update(data[:-16])
    data_size = len(data) - 16
    m.update(data_size.to_bytes(4, 'little'))
    m.update(version)
    m.update(b'TDF$')
    digest = m.digest()

    if digest != data[-16:]:
        raise ValueError('checksum mismatch (corrupted TDF file)')


# Source: https://github.com/Py0zz1/TelegramDesktop_Decrypt
def decrypt_key_datas(path, passcode):
    try:
        tdf_file_signature_check(path)
    except ValueError as e:
        exit(f"Cannot read key_datas file: {e}")

    with open(path, 'rb') as key_datas_file:
        key_datas = key_datas_file.read()

    print("\n##### key_datas parse #####")

    cur = 0x00
    header = key_datas[cur:cur+4]
    print(f"[HEADER] {header.decode('utf-8')}")

    cur += 0x04
    version = key_datas[cur:cur+4]
    print(f"[VERSION] {version.hex()}")

    cur += 0x04
    salt_len = int.from_bytes(key_datas[cur:cur+4], 'big')
    print(f"[SALT_LEN] {hex(salt_len)}")

    cur += 0x04
    salt = key_datas[cur:cur+salt_len]
    print(f"[SALT] {salt.hex()}")

    cur += salt_len
    localkey_block_len = int.from_bytes(key_datas[cur:cur+4], 'big')
    print(f"[LOCALKEY_BLOCK_LEN] {hex(localkey_block_len)}")

    cur += 0x04
    localkey_block = key_datas[cur:cur+localkey_block_len]
	
    cur += localkey_block_len
    info_len = int.from_bytes(key_datas[cur:cur+4], 'big')

    cur += 0x04
    info = key_datas[cur:cur+info_len]

    base_key = create_base_key(salt, passcode)

    try:
        localkey = generate_local_key(localkey_block, base_key)
    except ValueError as e:
        exit(f"Error while decrypting key_datas file: {e}")

    return localkey, info


####################################
##### settingss key generation #####
####################################

def create_settingss_key(salt):
    dst = hashlib.pbkdf2_hmac("sha1", b"", salt, 4, 256)

    print("\n##### Base key creation (settings) #####")
    print(f"[ALGORITHM] PKCS5_PBKDF2_HMAC_SHA1 (256B)")
    print(f"[BASE KEY] {dst.hex()}")

    return dst


def decrypt_settingss(path):
    try:
        tdf_file_signature_check(path)
    except ValueError as e:
        exit(f"Cannot read settingss file: {e}")

    with open(path, 'rb') as settingss_file:
        settingss = settingss_file.read()

    cur = 0x00
    print("\n#### key_datas parse #####")
    header = settingss[cur:cur+4]
    print(f"[HEADER] {header.decode('utf-8')}")

    cur += 0x04
    version = settingss[cur:cur+4]
    print(f"[VERSION] {version.hex()}")

    cur += 0x04
    salt_len = int.from_bytes(settingss[cur:cur+4], 'big')
    print(f"[SALT_LEN] {hex(salt_len)}")

    cur += 0x04
    salt = settingss[cur:cur+salt_len]
    print(f"[SALT] {salt.hex()}")

    base_key = create_settingss_key(salt)
    return base_key
