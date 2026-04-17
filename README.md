# Opgave 8 - Kryptografi med libsodium

Dette projekt indeholder små C++ eksempler til opgaverne i `6-cryptography.md`.

## Programmer

- `password_server`: opretter en password-hash med libsodium og gemmer den i `data/password_hash.txt`.
- `password_client`: læser password fra terminalen og verificerer det mod den gemte hash.
- `chap_demo`: viser en CHAP-lignende transaktion med fire packets.
- `encrypt_mac`: krypterer og dekrypterer en MAC-adresse med både symmetrisk og asymmetrisk kryptering.

## Installation af libsodium

Installér først libsodium. Vælg den metode der passer til dit system.

### Windows med vcpkg

Denne vej passer godt hvis du bruger Visual Studio eller Visual Studio Build Tools.

```powershell
git clone https://github.com/microsoft/vcpkg.git C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat
C:\vcpkg\vcpkg.exe install libsodium:x64-windows
```

Byg derefter med vcpkg toolchain-filen:

```powershell
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake
cmake --build build
```

### Ubuntu/Debian med apt

```bash
sudo apt update
sudo apt install build-essential cmake pkg-config libsodium-dev
```

Byg derefter:

```bash
cmake -S . -B build
cmake --build build
```

### Windows med MSYS2 UCRT64 og pacman

Denne vej passer godt hvis du bruger MinGW via MSYS2.

```bash
pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-pkgconf mingw-w64-ucrt-x86_64-libsodium
```

Byg derefter fra en MSYS2 UCRT64 terminal:

```bash
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build
```

Hvis CMake ikke kan finde libsodium, så kontrollér at du bruger samme terminal/toolchain til både installation og build.

## Kør eksemplerne

```powershell
.\build\password_server.exe
.\build\password_client.exe
.\build\chap_demo.exe
.\build\encrypt_mac.exe
```

## Kort refleksion

Hashing bruges når data ikke skal kunne genskabes. Passwords bør derfor hashes og verificeres, ikke krypteres. `crypto_pwhash_str` gemmer selv salt og algoritmeparametre i hash-strengen, så serveren kan verificere et senere password med `crypto_pwhash_str_verify`.

Kryptering bruges når data skal kunne læses igen senere. En MAC-adresse, device-id eller anden brugeroplysning kan derfor krypteres, hvis systemet senere har brug for originalværdien. Symmetrisk kryptering kræver at begge parter kender samme nøgle. Asymmetrisk kryptering bruger en public key til kryptering og en private key til dekryptering.

CHAP demonstrerer challenge-response: serveren sender en tilfældig challenge, klienten svarer med en hash/MAC over challengen og en delt hemmelighed, og serveren verificerer svaret. Dermed sendes hemmeligheden ikke direkte over forbindelsen.
