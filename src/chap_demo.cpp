#include "crypto_utils.h"

#include <iostream>

namespace {
constexpr std::size_t ChallengeBytes = 32;
}

int main() {
    try {
        crypto_demo::init_sodium();

        const std::string username = crypto_demo::read_line("Brugernavn: ");
        const std::string password = crypto_demo::read_hidden_line("Delt hemmelighed/password: ");

        std::cout << "\nPacket 1 - client -> server\n";
        std::cout << "Login request for bruger: " << username << "\n";

        const auto challenge = crypto_demo::random_bytes(ChallengeBytes);
        std::cout << "\nPacket 2 - server -> client\n";
        std::cout << "Challenge/salt: " << crypto_demo::bytes_to_hex(challenge) << "\n";

        const auto client_response = crypto_demo::chap_response(challenge, password);
        std::cout << "\nPacket 3 - client -> server\n";
        std::cout << "Response hash: "
                  << crypto_demo::bytes_to_hex(client_response.data(), client_response.size()) << "\n";

        const auto server_expected = crypto_demo::chap_response(challenge, password);
        const bool accepted = sodium_memcmp(
                                  client_response.data(),
                                  server_expected.data(),
                                  client_response.size()) == 0;

        std::cout << "\nPacket 4 - server -> client\n";
        std::cout << (accepted ? "ACK: login accepteret\n" : "NACK: login afvist\n");

        std::cout << "\nNote: Demoen simulerer klient og server i samme program. I et rigtigt system\n";
        std::cout << "skal serveren kunne verificere uden at gemme brugerens plaintext password.\n";
        return accepted ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << "Fejl: " << error.what() << "\n";
        return 1;
    }
}
