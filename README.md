# Half-life DLL decrypter and rebuilder 0.2

A decrypter and PE rebuilder for the Half-life encrypted DLLs like sw.dll, hw.dll and some client.dll (like that one of tfc16). Note that although the generated dll is correct seems to exist some checks in it or something similar which avoid the usage of the decrypted dll instead of the encrypted one, for example the game will load correctly but will crash at the multiplayer menu. So the main purpose is to analyze the clear dll.

## Credits

- Luigi Auriemma (2007-2008)
- Agustín dos Santos (2023) Update for Visual C++ 2022

## License
This sofware is released under GPL v2, please check out the [LICENSE](LICENSE) file for more information.


B#