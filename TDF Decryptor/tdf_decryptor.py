import argparse
import os
import sys
import shared_functions as sf


OUT_PATH = ""
PASSCODE = ""


def maps(content):
    len_start = 16
    content_start = len_start + 4
    content_len = int.from_bytes(content[len_start:content_start], 'big')
    return content[content_start:content_start+content_len]


def key_datas_dependent(content):
    len_start = 8
    content_start = len_start + 4
    content_len = int.from_bytes(content[len_start:content_start], 'big')
    return content[content_start:content_start+content_len]


def settings_dependent(content):
    len_start = 8
    content_start = len_start + 4
    content_len = int.from_bytes(content[len_start:content_start], 'big')
    return content[content_start:content_start+content_len]


def settingss(content):
    salt_len_start = 8
    salt_start = salt_len_start + 4
    salt_len = int.from_bytes(content[salt_len_start:salt_start], 'big')
    content_len_start = salt_start + salt_len
    content_start = content_len_start + 4
    content_len = int.from_bytes(content[content_len_start:content_start], 'big')
    return content[content_start:content_start+content_len]


def is_key_datas_dependent(filename, user_folders, path):
    return ("maps" in filename
            or "configs" in filename
            or (filename[:-1] in user_folders.keys())
            or (filename[:-3] in user_folders.keys())
            or (os.path.basename(os.path.dirname(path)) in user_folders.keys()))


def tdf_decrypt(filetype, filename, path):
    match filetype:
        case "key_datas":
            key_datas_key, key_datas_info = sf.decrypt_key_datas(path, bytes(PASSCODE, "ascii"))
            print("\n==> key_datas key successfully extracted!")
            with open(f"{OUT_PATH}\\keys\\key_datas.dat", "wb") as outfile:
                outfile.write(key_datas_key)

            content = sf.decrypt_local(key_datas_info, bytearray(key_datas_key))
            print(f"\n==> {filename} (info) successfully decrypted!")
            with open(f"{OUT_PATH}\\decrypted\\{filename}_info", "wb") as outfile:
                outfile.write(content)

        case "settingss":
            settingss_key = sf.decrypt_settingss(path)
            print("\n==> settingss key successfully extracted!")
            with open(f"{OUT_PATH}\\keys\\settingss.dat", "wb") as outfile:
                outfile.write(settingss_key)

            sf.tdf_file_signature_check(path)

            with open(path, "rb") as infile:
                encrypted_content = infile.read()
            content_to_decrypt = settingss(encrypted_content)
            content = sf.decrypt_local(content_to_decrypt, bytearray(settingss_key))
            print(f"\n==> {filename} successfully decrypted!")
            with open(f"{OUT_PATH}\\decrypted\\{filename}", "wb") as outfile:
                outfile.write(content)

        case "key_datas_dependent":
            with open(f"{OUT_PATH}\\keys\\key_datas.dat", "rb") as keyfile:
                key = keyfile.read()

            sf.tdf_file_signature_check(path)

            with open(path, "rb") as infile:
                encrypted_content = infile.read()
            if "maps" in filename:
                content_to_decrypt = maps(encrypted_content)
            else:
                content_to_decrypt = key_datas_dependent(encrypted_content)
            content = sf.decrypt_local(content_to_decrypt, bytearray(key))
            print(f"\n==> {filename} successfully decrypted!")
            with open(f"{OUT_PATH}\\decrypted\\{filename}", "wb") as outfile:
                outfile.write(content)

        case "settingss_dependent":
            with open(f"{OUT_PATH}\\keys\\settingss.dat", "rb") as keyfile:
                key = keyfile.read()

            sf.tdf_file_signature_check(path)

            with open(path, "rb") as infile:
                encrypted_content = infile.read()
            content_to_decrypt = settings_dependent(encrypted_content)
            content = sf.decrypt_local(content_to_decrypt, bytearray(key))
            print(f"\n==> {filename} successfully decrypted!")
            with open(f"{OUT_PATH}\\decrypted\\{filename}", "wb") as outfile:
                outfile.write(content)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog="TDF decryptor")
    parser.add_argument('-p', '--path',
                        help='path of the base directory containing Telegram Desktop',
                        required=True)
    parser.add_argument('-o', '--outdir', help='output path', required=True)
    parser.add_argument('-k', '--passkey', help='local passkey for Telegram Desktop session', required=True)
    args = parser.parse_args()

    datadir = args.path + "\\tdata"
    OUT_PATH = args.outdir
    PASSCODE = args.passkey

    tdf_files = dict()
    base_tdf_files = ["key_datas", "settingss"]
    user_folders = {"D877F783D5D3EF8C": 1, "A7FDF864FBC10B77": 2, "F8806DD0C461824F": 3}

    for root, _, files in os.walk(datadir):
        for filename in files:
            try:
                with open(os.path.join(root, filename), "rb") as file_content:
                    if file_content.read(4) == b"TDF$":
                        if is_key_datas_dependent(filename, user_folders, os.path.join(root, filename)):
                            if filename[:-1] in user_folders.keys():
                                tdf_files[f"{filename}#{user_folders[filename[:-1]]}"] = os.path.join(root, filename)
                            else:
                                tdf_files[f"{filename}#{user_folders[os.path.basename(os.path.dirname(os.path.join(root, filename)))]}"] = os.path.join(root, filename)
                        else:
                            tdf_files[filename] = os.path.join(root, filename)
            except PermissionError as e:
                print(f"Permission error: file '{filename}' ignored", file=sys.stdout)

    keys_path = f"{OUT_PATH}\\keys"
    if not os.path.exists(keys_path):
        os.mkdir(keys_path)
    files_path = f"{OUT_PATH}\\decrypted"
    if not os.path.exists(files_path):
        os.mkdir(files_path)

    tdf_decrypt("key_datas", "key_datas", tdf_files["key_datas"])
    tdf_decrypt("settingss", "settingss", tdf_files["settingss"])
    for filename in tdf_files.keys():
        if filename not in base_tdf_files:
            if is_key_datas_dependent(filename, user_folders, tdf_files[filename]):
                tdf_decrypt("key_datas_dependent", filename, tdf_files[filename])
            else:
                tdf_decrypt("settingss_dependent", filename, tdf_files[filename])

    print("\n\n##### ALL GOOD! #####")
