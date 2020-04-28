# Overcooked! 2 save decrypter/encrypter.
[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)  


## Summary
The game Overcooked! 2 made by Team17 encrypts its save files using the SteamID64 of the player. 

This tool allows decrypting and encrypting back the saves using any SteamID64. This is useful to either 
use a save file on another account, or to modify save games (decrypted saves are standard JSON).

## Usage
Python 3 required (tested on Python 3.7) with module pycryptodomex

### Decrypting a save:
python oc2_save.py decrypt [ENCRYPTED_SAVE_FILE.save] [DESIRED_OUTPUT_FILE.json] [YOUR_STEAMID64]

**Example:**
python oc2_save.py decrypt CoopSlot_SaveFile_0.save CoopSlot_SaveFile_0.json 76561111111111111

### Encrypting a save:
python oc2_save.py encrypt [DECRYPTED_SAVE_FILE.json] [DESIRED_OUTPUT_FILE.save] [YOUR_STEAMID64]

**Example:**
python oc2_save.py encrypt CoopSlot_SaveFile_0.json CoopSlot_SaveFile_0.save 76561111111111111


## Licensing
This software is licensed under the terms of Apache 2.0.  
You can find a copy of the license in the LICENSE file.