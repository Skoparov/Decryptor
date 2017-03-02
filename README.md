# Decryptor

A simple password decryptor for Triple DES 2-key encryption method, with the encrytion key made of 3 random characters from [0-9A-Za-z], and the Triple DES keys being the first and the second 8 bytes of MD5 of that key. The encrypted file is made of the 8 bytes of encryption header, the data itself and the 32 bytes of sha256 of said data.

Implemented using libssl and libcrypto, can only be built on linux.
