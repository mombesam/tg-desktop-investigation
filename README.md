# tg-desktop-investigation
Set of tools and documentation files for Telegram Desktop artifacts investigation.  
_Last tested with Telegram Desktop v4.11.5_.
**Requirements**:
* Python 3.x
* Windows OS


## General forensic workflow
The tools provided in this repository are part of a general forensic workflow for the analysis of local Telegram Desktop artifacts:
1. Perform a disk acquisition using forensic tools and methods (t is sufficient to acquire the Telegram Desktop folder, usually located at `C:\Users\<USER>\AppData\Roaming\Telegram Desktop`).
2. If a local passkey for Telegram Desktop has been set:
   * Use [telegram2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/telegram2john.py) to parse the file _key_datas_
   * Use [John the Ripper password cracker](https://www.openwall.com/john/) to crack the passkey using the previous output (this could require some time)
3. If a local passkey has not been set (or if the passkey is already known):
   * Use [TDF Decryptor](./TDF%20Decryptor/tdf_decryptor.py) to decrypt TDF files (see [TDF file structures](./TDF%20Decryptor/TDF%20file%20structures) for the detailed file structures)
   * Use [telegram-cache-decryption](https://github.com/lilydjwg/telegram-cache-decryption) to decrypt cache files (_user_data_ folder) and use [TGD Cache Parser](./TGD%20Cache%20Parser/tgd_cache_parser.py) to parse small files (less than 10MB) from the decrypted binary files. To deserialize bigger files, use [telegram-media-deserialize](https://github.com/AppleSheeple/telegram-media-deserialize)

## TGD Cache Parser
A Python tool that allows to parse the Telegram Desktop cache once decrypted using [telegram-cache-decryption by lilydjwg](https://github.com/lilydjwg/telegram-cache-decryption).  
**Note**: file headers and extensions are hard-coded in the source code. Feel free to add/modify any file type.  
**Usage**: `python tgd_cache_parser.py -p DECRYPTED_CACHE_PATH -o OUTPUT_PATH`


## TDF Decryptor
A Python tool that allows to decrypt TDFs (Telegram Desktop Files) contained in the _tdata_ folder of Telegram Desktop.  
A set of XML file structures describing the different TDF files is also available in _TDF file structures_.  
**Note**: the local passkey for Telegram Desktop must be known to decrypt TDFs.  
**Contributions**: main functions are adapted from [telegram-cache-decryption by lilydjwg](https://github.com/lilydjwg/telegram-cache-decryption) and [TelegramDesktop_Decrypt by Py0zz1](https://github.com/Py0zz1/TelegramDesktop_Decrypt).  
**Usage**: `python tdf_decryptor.py -p Telegram_Desktop_FOLDER_PATH -o OUTPUT_PATH -k LOCAL_KEY`  
**Requirements:** 
+ tgcrypto
