#ifndef ADATP_H
#define ADATP_H

#include <Arduino.h>
#include <Client.h>

#ifdef ESP32
#include <WiFi.h>
#include <mbedtls/gcm.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha1.h>
#include <mbedtls/base64.h>
#elif defined(ESP8266)
#include <ESP8266WiFi.h>
// ESP8266 BearSSL is different, sticking to ESP32 mbedTLS support for now
// or standard Arduino includes if mbedtls not present.
// For V2 Production, we focus on ESP32 primarily as requested.
#include <mbedtls/gcm.h>
#include <mbedtls/sha256.h>
#else
#include <SPI.h>
#include <Ethernet.h>
#endif

// Protocol Constants
#define ADATP_MAGIC 0x41444154
#define PROTOCOL_VERSION 1

// Message Types
#define MSG_HANDSHAKE_INIT  0x0001
#define MSG_HANDSHAKE_RESP  0x0002
#define MSG_HANDSHAKE_COMP  0x0003
#define MSG_AUTH_REQUEST    0x0010 // Auth Init
#define MSG_AUTH_CHALLENGE  0x0011
#define MSG_AUTH_PROVE      0x0012
#define MSG_AUTH_SUCCESS    0x0013 // Auth Result
#define MSG_TEXT            0x0020
#define MSG_GAME_STATE      0x0050
#define MSG_TOOL_CALL       0x0070
#define MSG_TOOL_RESULT     0x0071
#define MSG_TOOL_ERROR      0x0072
#define MSG_PING            0x0080
#define MSG_PONG            0x0081
#define MSG_JOIN_ROOM       0x00A0
#define MSG_ROOM_JOINED     0x00A1
#define MSG_DISCONNECT      0x00FF

// Packet Flags
#define FLAG_ENCRYPTED 0x0001

#pragma pack(push, 1)
struct PacketHeader {
    uint32_t magic;
    uint8_t version;
    uint16_t flags;
    uint32_t length;
    uint64_t sequence;
    uint16_t msg_type;
    uint64_t timestamp;
    uint8_t session_id[16];
};
#pragma pack(pop)

class AdaTP {
public:
    AdaTP(Client& client);
    ~AdaTP();
    
    // Connect to server over WebSocket (blocking handshake).
    // Default AdaTP port is 3000; the WebSocket path defaults to "/ws".
    bool connect(const char* host, uint16_t port, const char* username, const char* password,
                 const char* path = "/ws");

    // Main loop processing (must be called frequently)
    void loop();

    // Send Text Message
    void say(const char* text);

    // Join a room (encrypted; confirmation arrives asynchronously)
    void joinRoom(const char* room);

    // Broadcast a game state payload (JSON recommended) to the room
    void sendGameState(const char* json);
    
    // Event Callbacks
    typedef void (*ConnectCallback)();
    typedef void (*MessageCallback)(String from, String text);
    typedef void (*DisconnectCallback)();

    void onConnect(ConnectCallback cb);
    void onMessage(MessageCallback cb);
    void onDisconnect(DisconnectCallback cb);
    
    bool isConnected();

private:
    Client& _client;
    bool _connected;
    uint8_t _sessionId[16];
    uint64_t _txSeq;
    uint64_t _rxSeq;
    
    // Crypto State
    uint8_t _sharedSecret[32];
    uint8_t _clientWriteKey[32];
    uint8_t _serverWriteKey[32];
    uint8_t _clientIvRoot[12];
    uint8_t _serverIvRoot[12];
    bool _secure;
    
#ifdef ESP32
    // mbedTLS context (ESP32 hardware-accelerated AES-GCM)
    mbedtls_gcm_context _gcmCtx;
#endif
    
    ConnectCallback _onConnect;
    MessageCallback _onMessage;
    DisconnectCallback _onDisconnect;

    // Helpers
    bool performHandshake(const char* username, const char* password);
    void sendPacket(uint16_t type, const uint8_t* payload, size_t len, bool encrypted = false);
    bool parseHeader(const uint8_t* buf, PacketHeader& header);

    // WebSocket transport (minimal RFC 6455 client)
    bool wsHandshake(const char* host, uint16_t port, const char* path);
    bool wsSendFrame(uint8_t opcode, const uint8_t* payload, size_t len);
    // Reads the next complete binary message into a malloc'd buffer
    // (caller frees). Control frames are handled transparently.
    // Returns false on timeout/close.
    bool wsReadMessage(uint8_t** out, size_t* outLen, uint32_t timeoutMs);
    bool wsReadExact(uint8_t* buf, size_t len, uint32_t timeoutMs);
    
    // Crypto Implementations
    bool crypto_ecdh_keygen(uint8_t* pub, uint8_t* priv);
    bool crypto_ecdh_shared(const uint8_t* peerPub, const uint8_t* myPriv, uint8_t* secret);
    bool crypto_hkdf(const uint8_t* secret, uint8_t* outKey);
    bool crypto_encrypt(const uint8_t* plain, size_t len, uint8_t* cipher, uint8_t* tag, uint64_t seq);
    bool crypto_decrypt(const uint8_t* cipher, size_t len, const uint8_t* tag, uint8_t* plain, uint64_t seq);
};

#endif
