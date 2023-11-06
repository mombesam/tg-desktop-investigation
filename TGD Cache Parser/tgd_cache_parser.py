import os
import shutil
import sys
from pathlib import Path
import argparse

# File headers and extensions for each file type to parse (non-exhaustive)
MAGIC = {"JPG-JPEG": [b"\xFF\xD8\xFF"],
         "PNG": [b"\x89\x50\x4E\x47"],
         "RIFF-WEBPVP8": [b"\x52\x49\x46\x46"],
         "MP3": [b"\xFF\xFB", b"\xFF\xF3", b"\xFF\xF2", b"\x49\x44\x33"],
         "MOV": [b"\x00\x00\x00\x20\x66\x74\x79\x70"],
         "OGG": [b"\x4F\x67\x67\x53"],
         "TGS": [b"\x1F\x8B\x08"]}
FILESEXT = {"JPG-JPEG": ".jpg",
            "PNG": ".png",
            "RIFF-WEBPVP8": ".jpg",
            "MP3": ".mp3",
            "TGS": ".tgs",
            "MOV": ".mov",
            "OGG": ".ogg",
            "OTHER": "",
            "SERIALIZED": ""}

OUT_PATH = None
LOGFILE = "log.txt"


def magic_sort(file_path):
    magic_log = None
    filetype = None
    with open(file_path, "rb") as f_in:
        content = f_in.read()

    found = False
    for file_type, magic_list in MAGIC.items():
        for magic in magic_list:
            if content.startswith(magic):
                found = True
                if not(os.path.exists(f"{OUT_PATH}\\{file_type}")):
                    os.mkdir(f"{OUT_PATH}\\{file_type}")
                magic_log = magic
                filetype = file_type
                break
        if found:
            break
    if not found:
        if "media_cache" in file_path:
            if not (os.path.exists(f"{OUT_PATH}\\SERIALIZED")):
                os.mkdir(f"{OUT_PATH}\\SERIALIZED")
            magic_log = content[:8]
            filetype = "SERIALIZED"
            print("Possible serialized file(s) found! Check the dir structure in 'media_cache' and deserialize accordingly!", file=sys.stdout)
        else:
            if not (os.path.exists(f"{OUT_PATH}\\OTHER")):
                os.mkdir(f"{OUT_PATH}\\OTHER")
            magic_log = content[:8]
            filetype = "OTHER"

    path = f"{OUT_PATH}\\{filetype}"
    shutil.copy(file_path, path)
    new_path = Path(f"{OUT_PATH}\\{filetype}\\{os.path.basename(file_path)}")
    new_path.rename(new_path.with_suffix(FILESEXT[filetype]))
    magic_format = " ".join([f"0x{byte:02X}" for byte in magic_log])
    with open(f"{OUT_PATH}\\{LOGFILE}", "a") as log:
        log.write(f"{os.path.basename(file_path)} ({filetype})\t\t\t{magic_format}\n")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog="TGD Cache Parser")
    parser.add_argument('-p', '--path', help='path of the base directory containing Telegram Desktop decrypted cache files', required=True)
    parser.add_argument('-o', '--outdir', help='output path', required=True)
    args = parser.parse_args()

    datadir = args.path.replace("\\", "\\\\")
    OUT_PATH = args.outdir.replace("\\", "\\\\") + "\\result"
    os.mkdir(OUT_PATH)

    with open(f"{OUT_PATH}\\{LOGFILE}", "w") as log_content:
        log_content.write("##### Parsed files #####\n\n")
    for root, _, files in os.walk(datadir):
        for name in files:
            magic_sort(os.path.join(root, name))
