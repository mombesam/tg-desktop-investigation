# tg-desktop-investigation
Set of tools and documentatio files for Telegram Desktop artifacts investigation.  
_Last tested with Telegram Desktop v4.11.3_.


## General forensic workflow
TODO


## TGD Cache Parser
A Python tool that allows to parse the Telegram Desktop cache once decrypted using [telegram-cache-decryption by lilydjwg](https://github.com/lilydjwg/telegram-cache-decryption).  
**Note**: file headers and extensions are hard-coded in the source code. Feel free to add/modify any file type.  
**Usage**: `python tgd_cache_parser.py -p DECRYPTED_CACHE_PATH -o OUTPUT_PATH`


## TDF Decryptor
A Python tool that allows to decrypt TDFs (Telegram Desktop Files) contained in the _tdata_ folder of Telegram Desktop.  
A set of XML file structures describing the different TDF files is also available in _TDF file structures_.  
**Note**: the local passkey for Telegram Desktop must be known to decrypt TDFs.  
**Contributions**: main functions are adapted from [telegram-cache-decryption by lilydjwg](https://github.com/lilydjwg/telegram-cache-decryption) and [TelegramDesktop_Decrypt by Py0zz1](https://github.com/Py0zz1/TelegramDesktop_Decrypt).  
**Usage**: `python tdf_decryptor.py -p tdata_FOLDER_PATH -o OUTPUT_PATH -k LOCAL_KEY`  
**Requirements:** 
+ tgcrypto
