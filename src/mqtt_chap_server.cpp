#include "crypto_utils.h"

#include <mosquitto.h>

#include <cerrno>
#include <cstring>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr const char* StartTopic = "opgave8/chap/start";
constexpr const char* ResponseTopic = "opgave8/chap/response/+";
constexpr std::size_t ChallengeBytes = 32;

struct ServerContext {
    std::string shared_secret;
    std::map<std::string, std::vector<unsigned char>> challenges;
};

std::string mqtt_connect_error(const int rc) {
    std::string error = mosquitto_strerror(rc);
    if (rc == MOSQ_ERR_ERRNO) {
        error += ": ";
        error += std::strerror(errno);
        if (errno == 0) {
            error += ". Er Mosquitto broker startet paa denne host/port?";
        }
    }
    return error + " (kode " + std::to_string(rc) + ")";
}

std::string payload_to_string(const mosquitto_message* message) {
    return std::string(
        static_cast<const char*>(message->payload),
        static_cast<std::size_t>(message->payloadlen));
}

std::string topic_suffix(const std::string& topic, const std::string& prefix) {
    if (topic.rfind(prefix, 0) != 0) {
        return "";
    }
    return topic.substr(prefix.size());
}

void publish_text(mosquitto* client, const std::string& topic, const std::string& text) {
    mosquitto_publish(
        client,
        nullptr,
        topic.c_str(),
        static_cast<int>(text.size()),
        text.c_str(),
        0,
        false);
}

void on_connect(mosquitto* client, void*, int rc) {
    if (rc != 0) {
        std::cerr << "MQTT connect fejlede med kode " << rc << "\n";
        return;
    }

    mosquitto_subscribe(client, nullptr, StartTopic, 0);
    mosquitto_subscribe(client, nullptr, ResponseTopic, 0);
    std::cout << "CHAP server lytter paa " << StartTopic << " og " << ResponseTopic << "\n";
}

void handle_start(mosquitto* client, ServerContext* context, const std::string& username) {
    const auto challenge = crypto_demo::random_bytes(ChallengeBytes);
    context->challenges[username] = challenge;

    const std::string challenge_hex = crypto_demo::bytes_to_hex(challenge);
    publish_text(client, "opgave8/chap/challenge/" + username, challenge_hex);

    std::cout << "Packet 2: sendte challenge til " << username << ": " << challenge_hex << "\n";
}

void handle_response(
    mosquitto* client,
    ServerContext* context,
    const std::string& username,
    const std::string& response_hex) {
    const auto challenge_it = context->challenges.find(username);
    if (challenge_it == context->challenges.end()) {
        publish_text(client, "opgave8/chap/result/" + username, "AFVIST: ingen challenge");
        return;
    }

    const auto expected = crypto_demo::chap_response(challenge_it->second, context->shared_secret);
    bool accepted = false;
    try {
        const auto received = crypto_demo::hex_to_bytes(response_hex);
        accepted = received.size() == expected.size()
            && sodium_memcmp(received.data(), expected.data(), expected.size()) == 0;
    } catch (const std::exception& error) {
        std::cerr << "Ugyldigt response fra " << username << ": " << error.what() << "\n";
    }

    context->challenges.erase(challenge_it);
    const std::string result = accepted ? "OK" : "AFVIST";
    publish_text(client, "opgave8/chap/result/" + username, result);

    std::cout << "Packet 4: " << username << " -> " << result << "\n";
}

void on_message(mosquitto* client, void* userdata, const mosquitto_message* message) {
    auto* context = static_cast<ServerContext*>(userdata);
    const std::string topic = message->topic;
    const std::string payload = payload_to_string(message);

    if (topic == StartTopic) {
        std::cout << "Packet 1: login request fra " << payload << "\n";
        handle_start(client, context, payload);
        return;
    }

    const std::string username = topic_suffix(topic, "opgave8/chap/response/");
    if (!username.empty()) {
        std::cout << "Packet 3: modtog response fra " << username << "\n";
        handle_response(client, context, username, payload);
    }
}

} // namespace

int main(int argc, char* argv[]) {
    try {
        crypto_demo::init_sodium();
        const std::string host = argc > 1 ? argv[1] : "127.0.0.1";
        const int port = argc > 2 ? std::stoi(argv[2]) : 1883;

        ServerContext context;
        context.shared_secret = crypto_demo::read_hidden_line("Serverens delte hemmelighed/password: ");

        mosquitto_lib_init();
        mosquitto* client = mosquitto_new("opgave8-chap-server", true, &context);
        if (!client) {
            throw std::runtime_error("Kunne ikke oprette MQTT client");
        }

        mosquitto_connect_callback_set(client, on_connect);
        mosquitto_message_callback_set(client, on_message);

        const int rc = mosquitto_connect(client, host.c_str(), port, 60);
        if (rc != MOSQ_ERR_SUCCESS) {
            throw std::runtime_error(std::string("MQTT connect fejlede: ") + mqtt_connect_error(rc));
        }

        std::cout << "Forbundet til MQTT broker " << host << ":" << port << "\n";
        mosquitto_loop_forever(client, -1, 1);

        mosquitto_destroy(client);
        mosquitto_lib_cleanup();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Fejl: " << error.what() << "\n";
        mosquitto_lib_cleanup();
        return 1;
    }
}
