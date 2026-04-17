#include "crypto_utils.h"

#include <algorithm>
#include <iostream>

int main() {
    try {
        crypto_demo::init_sodium();

        std::string stored_hash = crypto_demo::read_text_file("data/password_hash.txt");
        stored_hash.erase(std::remove(stored_hash.begin(), stored_hash.end(), '\r'), stored_hash.end());
        stored_hash.erase(std::remove(stored_hash.begin(), stored_hash.end(), '\n'), stored_hash.end());

        const std::string password = crypto_demo::read_hidden_line("Indtast password: ");

        const int result = crypto_pwhash_str_verify(
            stored_hash.c_str(),
            password.c_str(),
            password.size());

        if (result == 0) {
            std::cout << "OK: password matcher den gemte hash.\n";
            return 0;
        }

        std::cout << "Afvist: password matcher ikke.\n";
        return 1;
    } catch (const std::exception& error) {
        std::cerr << "Fejl: " << error.what() << "\n";
        return 1;
    }
}
