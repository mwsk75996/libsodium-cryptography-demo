#pragma once

#include <array>
#include <cstddef>
#include <string>
#include <vector>

#include <sodium.h>

namespace crypto_demo {

void init_sodium();

std::string bytes_to_hex(const unsigned char* data, std::size_t size);
std::string bytes_to_hex(const std::vector<unsigned char>& data);

std::vector<unsigned char> random_bytes(std::size_t size);

std::string read_hidden_line(const std::string& prompt);
std::string read_line(const std::string& prompt);

void write_text_file(const std::string& path, const std::string& content);
std::string read_text_file(const std::string& path);

std::array<unsigned char, crypto_auth_KEYBYTES> key_from_password(const std::string& password);
std::array<unsigned char, crypto_auth_BYTES> chap_response(
    const std::vector<unsigned char>& challenge,
    const std::string& password);

} // namespace crypto_demo
