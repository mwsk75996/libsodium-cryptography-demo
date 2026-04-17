#include "crypto_utils.h"

#include <cstring>
#include <iostream>
#include <stdexcept>

int main() {
    try {
        crypto_demo::init_sodium();

        const std::string password = crypto_demo::read_hidden_line("Opret password: ");
        if (password.empty()) {
            std::cerr << "Password maa ikke vaere tomt.\n";
            return 1;
        }

        char hashed_password[crypto_pwhash_STRBYTES];
        if (crypto_pwhash_str(
                hashed_password,
                password.c_str(),
                password.size(),
                crypto_pwhash_OPSLIMIT_INTERACTIVE,
                crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
            throw std::runtime_error("Ikke nok hukommelse til password hashing");
        }

        crypto_demo::write_text_file("data/password_hash.txt", std::string(hashed_password) + "\n");
        std::cout << "Password hash er gemt i data/password_hash.txt\n";
        std::cout << "Hash: " << hashed_password << "\n";

        sodium_memzero(hashed_password, sizeof hashed_password);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Fejl: " << error.what() << "\n";
        return 1;
    }
}
