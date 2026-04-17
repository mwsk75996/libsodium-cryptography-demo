#include "crypto_utils.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace crypto_demo {

void init_sodium() {
    if (sodium_init() < 0) {
        throw std::runtime_error("libsodium kunne ikke initialiseres");
    }
}

std::string bytes_to_hex(const unsigned char* data, const std::size_t size) {
    std::string hex(size * 2 + 1, '\0');
    sodium_bin2hex(hex.data(), hex.size(), data, size);
    hex.pop_back();
    return hex;
}

std::string bytes_to_hex(const std::vector<unsigned char>& data) {
    return bytes_to_hex(data.data(), data.size());
}

std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("Hex string har ulige laengde");
    }

    std::vector<unsigned char> bytes(hex.size() / 2);
    std::size_t bin_len = 0;
    if (sodium_hex2bin(
            bytes.data(),
            bytes.size(),
            hex.c_str(),
            hex.size(),
            nullptr,
            &bin_len,
            nullptr) != 0) {
        throw std::runtime_error("Ugyldig hex string");
    }

    bytes.resize(bin_len);
    return bytes;
}

std::string generic_hash_hex(const std::string& value) {
    std::array<unsigned char, crypto_generichash_BYTES> hash{};
    crypto_generichash(
        hash.data(),
        hash.size(),
        reinterpret_cast<const unsigned char*>(value.data()),
        value.size(),
        nullptr,
        0);
    return bytes_to_hex(hash.data(), hash.size());
}

bool constant_time_equal_hex(const std::string& left, const std::string& right) {
    const auto left_bytes = hex_to_bytes(left);
    const auto right_bytes = hex_to_bytes(right);
    if (left_bytes.size() != right_bytes.size()) {
        return false;
    }

    return sodium_memcmp(left_bytes.data(), right_bytes.data(), left_bytes.size()) == 0;
}

std::vector<unsigned char> random_bytes(const std::size_t size) {
    std::vector<unsigned char> bytes(size);
    randombytes_buf(bytes.data(), bytes.size());
    return bytes;
}

std::string read_hidden_line(const std::string& prompt) {
    // Standard C++ kan ikke skjule terminalinput portabelt uden ekstra platformskode.
    return read_line(prompt);
}

std::string read_line(const std::string& prompt) {
    std::cout << prompt;
    std::string value;
    std::getline(std::cin, value);
    return value;
}

void write_text_file(const std::string& path, const std::string& content) {
    const std::filesystem::path file_path(path);
    if (file_path.has_parent_path()) {
        std::filesystem::create_directories(file_path.parent_path());
    }

    std::ofstream file(file_path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Kunne ikke skrive fil: " + path);
    }
    file << content;
}

std::string read_text_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Kunne ikke laese fil: " + path);
    }

    return std::string(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
}

std::array<unsigned char, crypto_auth_KEYBYTES> key_from_password(const std::string& password) {
    std::array<unsigned char, crypto_auth_KEYBYTES> key{};
    crypto_generichash(
        key.data(),
        key.size(),
        reinterpret_cast<const unsigned char*>(password.data()),
        password.size(),
        nullptr,
        0);
    return key;
}

std::array<unsigned char, crypto_auth_BYTES> chap_response(
    const std::vector<unsigned char>& challenge,
    const std::string& password) {
    const auto key = key_from_password(password);
    std::array<unsigned char, crypto_auth_BYTES> response{};

    crypto_auth(response.data(), challenge.data(), challenge.size(), key.data());
    return response;
}

} // namespace crypto_demo
