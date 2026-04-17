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

constexpr const char* StartTopic = "opgave8/chap/start";

struct ClientContext {
    std::mutex mutex;
    std::condition_variable cv;
    std::string username;
    std::string shared_secret;
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

void on_connect(mosquitto* client, void* userdata, int rc) {
    auto* context = static_cast<ClientContext*>(userdata);
    if (rc != 0) {
        std::cerr << "MQTT connect fejlede med kode " << rc << "\n";
        return;
    }

    mosquitto_subscribe(client, nullptr, ("opgave8/chap/challenge/" + context->username).c_str(), 0);
    mosquitto_subscribe(client, nullptr, ("opgave8/chap/result/" + context->username).c_str(), 0);

    publish_text(client, StartTopic, context->username);
    std::cout << "Packet 1: sendte login request for " << context->username << "\n";
}

void on_message(mosquitto* client, void* userdata, const mosquitto_message* message) {
    auto* context = static_cast<ClientContext*>(userdata);
    const std::string topic = message->topic;
    const std::string payload = payload_to_string(message);

    const std::string challenge_topic = "opgave8/chap/challenge/" + context->username;
    const std::string result_topic = "opgave8/chap/result/" + context->username;

    if (topic == challenge_topic) {
        try {
            const auto challenge = crypto_demo::hex_to_bytes(payload);
            const auto response = crypto_demo::chap_response(challenge, context->shared_secret);
            const std::string response_hex = crypto_demo::bytes_to_hex(response.data(), response.size());
            publish_text(client, "opgave8/chap/response/" + context->username, response_hex);
            std::cout << "Packet 3: sendte response hash\n";
        } catch (const std::exception& error) {
            std::cerr << "Kunne ikke behandle challenge: " << error.what() << "\n";
        }
        return;
    }

    if (topic == result_topic) {
        {
            std::lock_guard<std::mutex> lock(context->mutex);
            context->result = payload;
            context->done = true;
        }
        context->cv.notify_one();
    }
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
        context.shared_secret = crypto_demo::read_hidden_line("Delt hemmelighed/password: ");

        mosquitto_lib_init();
        client = mosquitto_new(nullptr, true, &context);
        if (!client) {
            throw std::runtime_error("Kunne ikke oprette MQTT client");
        }

        mosquitto_connect_callback_set(client, on_connect);
        mosquitto_message_callback_set(client, on_message);

        const int rc = mosquitto_connect(client, host.c_str(), port, 60);
        if (rc != MOSQ_ERR_SUCCESS) {
            throw std::runtime_error(std::string("MQTT connect fejlede: ") + mqtt_connect_error(rc));
        }

        mosquitto_loop_start(client);

        std::unique_lock<std::mutex> lock(context.mutex);
        if (!context.cv.wait_for(lock, std::chrono::seconds(10), [&context] { return context.done; })) {
            throw std::runtime_error("Timeout mens klienten ventede paa CHAP resultat");
        }

        std::cout << "Packet 4: server svar: " << context.result << "\n";

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
