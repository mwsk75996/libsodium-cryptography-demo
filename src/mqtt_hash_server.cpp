#include "crypto_utils.h"

#include <mosquitto.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

constexpr const char* LoginTopic = "opgave8/hash/login";
constexpr const char* HashFile = "data/mqtt_password_hash.txt";

struct ServerContext {
    std::string stored_hash;
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

void on_connect(mosquitto* client, void*, int rc) {
    if (rc != 0) {
        std::cerr << "MQTT connect fejlede med kode " << rc << "\n";
        return;
    }

    mosquitto_subscribe(client, nullptr, LoginTopic, 0);
    std::cout << "Server lytter paa topic: " << LoginTopic << "\n";
}

void on_message(mosquitto* client, void* userdata, const mosquitto_message* message) {
    auto* context = static_cast<ServerContext*>(userdata);
    const std::string payload = payload_to_string(message);
    const auto separator = payload.find(':');
    if (separator == std::string::npos) {
        std::cerr << "Afvist payload uden ':' separator\n";
        return;
    }

    const std::string username = payload.substr(0, separator);
    const std::string received_hash = payload.substr(separator + 1);

    bool accepted = false;
    try {
        accepted = crypto_demo::constant_time_equal_hex(received_hash, context->stored_hash);
    } catch (const std::exception& error) {
        std::cerr << "Afvist ugyldig hash fra " << username << ": " << error.what() << "\n";
    }

    const std::string result_topic = "opgave8/hash/result/" + username;
    const std::string result = accepted ? "OK" : "AFVIST";
    mosquitto_publish(
        client,
        nullptr,
        result_topic.c_str(),
        static_cast<int>(result.size()),
        result.c_str(),
        0,
        false);

    std::cout << "Login fra " << username << ": " << result << "\n";
}

} // namespace

int main(int argc, char* argv[]) {
    try {
        crypto_demo::init_sodium();
        const std::string host = argc > 1 ? argv[1] : "127.0.0.1";
        const int port = argc > 2 ? std::stoi(argv[2]) : 1883;

        ServerContext context;
        try {
            context.stored_hash = crypto_demo::read_text_file(HashFile);
            context.stored_hash.erase(
                std::remove(context.stored_hash.begin(), context.stored_hash.end(), '\r'),
                context.stored_hash.end());
            context.stored_hash.erase(
                std::remove(context.stored_hash.begin(), context.stored_hash.end(), '\n'),
                context.stored_hash.end());
        } catch (...) {
            const std::string password = crypto_demo::read_hidden_line("Opret MQTT password: ");
            context.stored_hash = crypto_demo::generic_hash_hex(password);
            crypto_demo::write_text_file(HashFile, context.stored_hash + "\n");
            std::cout << "Gemte hash i " << HashFile << "\n";
        }

        mosquitto_lib_init();
        mosquitto* client = mosquitto_new("opgave8-hash-server", true, &context);
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
