#include "crypto_utils.h"

#include <mosquitto.h>

#include <cerrno>
#include <condition_variable>
#include <cstring>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>

namespace {

constexpr const char* LoginTopic = "opgave8/hash/login";

struct ClientContext {
    std::mutex mutex;
    std::condition_variable cv;
    std::string username;
    std::string result;
    bool done = false;
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

void on_connect(mosquitto* client, void* userdata, int rc) {
    auto* context = static_cast<ClientContext*>(userdata);
    if (rc != 0) {
        std::cerr << "MQTT connect fejlede med kode " << rc << "\n";
        return;
    }

    const std::string result_topic = "opgave8/hash/result/" + context->username;
    mosquitto_subscribe(client, nullptr, result_topic.c_str(), 0);
}

void on_message(mosquitto*, void* userdata, const mosquitto_message* message) {
    auto* context = static_cast<ClientContext*>(userdata);
    {
        std::lock_guard<std::mutex> lock(context->mutex);
        context->result = payload_to_string(message);
        context->done = true;
    }
    context->cv.notify_one();
}

} // namespace

int main(int argc, char* argv[]) {
    mosquitto* client = nullptr;
    try {
        crypto_demo::init_sodium();
        const std::string host = argc > 1 ? argv[1] : "127.0.0.1";
        const int port = argc > 2 ? std::stoi(argv[2]) : 1883;

        ClientContext context;
        context.username = crypto_demo::read_line("Brugernavn: ");
        const std::string password = crypto_demo::read_hidden_line("Password: ");
        const std::string password_hash = crypto_demo::generic_hash_hex(password);
        const std::string payload = context.username + ":" + password_hash;

        mosquitto_lib_init();
        client = mosquitto_new(nullptr, true, &context);
        if (!client) {
            throw std::runtime_error("Kunne ikke oprette MQTT client");
        }

        mosquitto_connect_callback_set(client, on_connect);
        mosquitto_message_callback_set(client, on_message);

        int rc = mosquitto_connect(client, host.c_str(), port, 60);
        if (rc != MOSQ_ERR_SUCCESS) {
            throw std::runtime_error(std::string("MQTT connect fejlede: ") + mqtt_connect_error(rc));
        }

        mosquitto_loop_start(client);
        mosquitto_publish(
            client,
            nullptr,
            LoginTopic,
            static_cast<int>(payload.size()),
            payload.c_str(),
            0,
            false);

        std::unique_lock<std::mutex> lock(context.mutex);
        if (!context.cv.wait_for(lock, std::chrono::seconds(10), [&context] { return context.done; })) {
            throw std::runtime_error("Timeout mens klienten ventede paa serverens MQTT svar");
        }

        std::cout << "Server svar: " << context.result << "\n";

        mosquitto_disconnect(client);
        mosquitto_loop_stop(client, true);
        mosquitto_destroy(client);
        mosquitto_lib_cleanup();
        return context.result == "OK" ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << "Fejl: " << error.what() << "\n";
        if (client) {
            mosquitto_disconnect(client);
            mosquitto_loop_stop(client, true);
            mosquitto_destroy(client);
        }
        mosquitto_lib_cleanup();
        return 1;
    }
}
