#include "crypto_utils.h"

#include <array>
#include <iostream>
#include <string>
#include <vector>

namespace {

std::string decrypt_secretbox(
    const std::vector<unsigned char>& ciphertext,
    const std::array<unsigned char, crypto_secretbox_KEYBYTES>& key,
    const std::array<unsigned char, crypto_secretbox_NONCEBYTES>& nonce) {
    std::vector<unsigned char> decrypted(ciphertext.size() - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(
            decrypted.data(),
            ciphertext.data(),
            ciphertext.size(),
            nonce.data(),
            key.data()) != 0) {
        throw std::runtime_error("Symmetrisk dekryptering fejlede");
    }

    return std::string(decrypted.begin(), decrypted.end());
}

std::string decrypt_sealed_box(
    const std::vector<unsigned char>& ciphertext,
    const std::array<unsigned char, crypto_box_PUBLICKEYBYTES>& public_key,
    const std::array<unsigned char, crypto_box_SECRETKEYBYTES>& secret_key) {
    std::vector<unsigned char> decrypted(ciphertext.size() - crypto_box_SEALBYTES);
    if (crypto_box_seal_open(
            decrypted.data(),
            ciphertext.data(),
            ciphertext.size(),
            public_key.data(),
            secret_key.data()) != 0) {
        throw std::runtime_error("Asymmetrisk dekryptering fejlede");
    }

    return std::string(decrypted.begin(), decrypted.end());
}

} // namespace

int main() {
    try {
        crypto_demo::init_sodium();

        const std::string mac_address = crypto_demo::read_line("MAC-adresse [AA:BB:CC:DD:EE:FF]: ");
        const std::string plaintext = mac_address.empty() ? "AA:BB:CC:DD:EE:FF" : mac_address;
        const auto* message = reinterpret_cast<const unsigned char*>(plaintext.data());

        std::array<unsigned char, crypto_secretbox_KEYBYTES> symmetric_key{};
        std::array<unsigned char, crypto_secretbox_NONCEBYTES> nonce{};
        randombytes_buf(symmetric_key.data(), symmetric_key.size());
        randombytes_buf(nonce.data(), nonce.size());

        std::vector<unsigned char> symmetric_ciphertext(plaintext.size() + crypto_secretbox_MACBYTES);
        crypto_secretbox_easy(
            symmetric_ciphertext.data(),
            message,
            plaintext.size(),
            nonce.data(),
            symmetric_key.data());

        std::cout << "\nSymmetrisk kryptering (crypto_secretbox_easy)\n";
        std::cout << "Ciphertext: " << crypto_demo::bytes_to_hex(symmetric_ciphertext) << "\n";
        std::cout << "Dekrypteret: " << decrypt_secretbox(symmetric_ciphertext, symmetric_key, nonce) << "\n";

        std::array<unsigned char, crypto_box_PUBLICKEYBYTES> public_key{};
        std::array<unsigned char, crypto_box_SECRETKEYBYTES> secret_key{};
        crypto_box_keypair(public_key.data(), secret_key.data());

        std::vector<unsigned char> asymmetric_ciphertext(plaintext.size() + crypto_box_SEALBYTES);
        crypto_box_seal(
            asymmetric_ciphertext.data(),
            message,
            plaintext.size(),
            public_key.data());

        std::cout << "\nAsymmetrisk kryptering (crypto_box_seal)\n";
        std::cout << "Public key: " << crypto_demo::bytes_to_hex(public_key.data(), public_key.size()) << "\n";
        std::cout << "Ciphertext: " << crypto_demo::bytes_to_hex(asymmetric_ciphertext) << "\n";
        std::cout << "Dekrypteret: " << decrypt_sealed_box(asymmetric_ciphertext, public_key, secret_key) << "\n";

        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Fejl: " << error.what() << "\n";
        return 1;
    }
}
