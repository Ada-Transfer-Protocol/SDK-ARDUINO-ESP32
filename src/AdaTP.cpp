#include "AdaTP.h"

// Helper for endian swap (mbedTLS MPI is BE, X25519 is LE)
void reverseBytes(uint8_t* start, size_t size) {
    for(size_t i=0; i<size/2; i++) {
        uint8_t t = start[i];
        start[i] = start[size-1-i];
        start[size-1-i] = t;
    }
}

#define ADATP_WS_MAX_MESSAGE 8192

AdaTP::AdaTP(Client& client) : _client(client) {
    _connected = false;
    _txSeq = 0;
    _rxSeq = 0;
    _secure = false;
    _onConnect = NULL;
    _onMessage = NULL;
    _onDisconnect = NULL;
    for(int i=0; i<16; i++) _sessionId[i] = random(0, 255);

#ifdef ESP32
    mbedtls_gcm_init(&_gcmCtx);
#endif
}

AdaTP::~AdaTP() {
#ifdef ESP32
    mbedtls_gcm_free(&_gcmCtx);
#endif
}

void AdaTP::onConnect(ConnectCallback cb) { _onConnect = cb; }
void AdaTP::onMessage(MessageCallback cb) { _onMessage = cb; }
void AdaTP::onDisconnect(DisconnectCallback cb) { _onDisconnect = cb; }
bool AdaTP::isConnected() { return _connected; }

// -------------------------------------------------------------------------
// WEBSOCKET TRANSPORT (minimal RFC 6455 client, binary messages only)
// -------------------------------------------------------------------------

bool AdaTP::wsReadExact(uint8_t* buf, size_t len, uint32_t timeoutMs) {
    size_t got = 0;
    unsigned long start = millis();
    while (got < len) {
        if (millis() - start > timeoutMs) return false;
        if (!_client.connected()) return false;
        int avail = _client.available();
        if (avail > 0) {
            int r = _client.read(buf + got, len - got);
            if (r > 0) got += r;
        } else {
            delay(1);
        }
    }
    return true;
}

bool AdaTP::wsHandshake(const char* host, uint16_t port, const char* path) {
    // Random 16-byte key, base64 encoded
    uint8_t keyRaw[16];
    for (int i = 0; i < 16; i++) keyRaw[i] = random(0, 255);

    char keyB64[32] = {0};
#ifdef ESP32
    size_t olen = 0;
    mbedtls_base64_encode((unsigned char*)keyB64, sizeof(keyB64), &olen, keyRaw, 16);
#else
    // Static key fallback for platforms without mbedtls base64
    strcpy(keyB64, "QWRhVFBBcmR1aW5vS2V5MDE=");
#endif

    String req = String("GET ") + path + " HTTP/1.1\r\n" +
                 "Host: " + host + ":" + String(port) + "\r\n" +
                 "Upgrade: websocket\r\n" +
                 "Connection: Upgrade\r\n" +
                 "Sec-WebSocket-Key: " + keyB64 + "\r\n" +
                 "Sec-WebSocket-Version: 13\r\n\r\n";
    _client.print(req);

    // Read response headers (until blank line)
    String response = "";
    unsigned long start = millis();
    while (millis() - start < 5000) {
        while (_client.available()) {
            char c = (char)_client.read();
            response += c;
            if (response.endsWith("\r\n\r\n")) goto headers_done;
            if (response.length() > 4096) return false;
        }
        if (!_client.connected()) return false;
        delay(1);
    }
    return false;

headers_done:
    if (response.indexOf(" 101 ") < 0) return false;

#ifdef ESP32
    {
        // Verify Sec-WebSocket-Accept = base64(SHA1(key + GUID))
        String src = String(keyB64) + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        uint8_t sha[20];
        mbedtls_sha1((const unsigned char*)src.c_str(), src.length(), sha);
        char acceptB64[40] = {0};
        size_t alen = 0;
        mbedtls_base64_encode((unsigned char*)acceptB64, sizeof(acceptB64), &alen, sha, 20);
        if (response.indexOf(acceptB64) < 0) return false;
    }
#endif
    return true;
}

bool AdaTP::wsSendFrame(uint8_t opcode, const uint8_t* payload, size_t len) {
    uint8_t header[14];
    size_t hlen = 0;
    header[hlen++] = 0x80 | opcode; // FIN + opcode

    if (len < 126) {
        header[hlen++] = 0x80 | (uint8_t)len; // MASK + len
    } else if (len < 65536) {
        header[hlen++] = 0x80 | 126;
        header[hlen++] = (len >> 8) & 0xFF;
        header[hlen++] = len & 0xFF;
    } else {
        return false; // larger messages are not supported on embedded targets
    }

    uint8_t mask[4];
    for (int i = 0; i < 4; i++) mask[i] = random(0, 255);
    memcpy(header + hlen, mask, 4);
    hlen += 4;

    if (_client.write(header, hlen) != hlen) return false;

    // Mask and send in small chunks to keep RAM usage flat.
    uint8_t chunk[256];
    size_t sent = 0;
    while (sent < len) {
        size_t n = len - sent;
        if (n > sizeof(chunk)) n = sizeof(chunk);
        for (size_t i = 0; i < n; i++) chunk[i] = payload[sent + i] ^ mask[(sent + i) % 4];
        if (_client.write(chunk, n) != n) return false;
        sent += n;
    }
    return true;
}

bool AdaTP::wsReadMessage(uint8_t** out, size_t* outLen, uint32_t timeoutMs) {
    uint8_t* message = NULL;
    size_t messageLen = 0;
    bool inBinary = false;
    unsigned long start = millis();

    while (millis() - start < timeoutMs) {
        uint8_t head[2];
        if (!wsReadExact(head, 2, timeoutMs)) { free(message); return false; }

        bool fin = (head[0] & 0x80) != 0;
        uint8_t opcode = head[0] & 0x0F;
        bool masked = (head[1] & 0x80) != 0;
        uint32_t len = head[1] & 0x7F;

        if (len == 126) {
            uint8_t ext[2];
            if (!wsReadExact(ext, 2, timeoutMs)) { free(message); return false; }
            len = ((uint32_t)ext[0] << 8) | ext[1];
        } else if (len == 127) {
            uint8_t ext[8];
            if (!wsReadExact(ext, 8, timeoutMs)) { free(message); return false; }
            // Only the low 32 bits are usable on embedded targets.
            len = ((uint32_t)ext[4] << 24) | ((uint32_t)ext[5] << 16) |
                  ((uint32_t)ext[6] << 8) | ext[7];
        }
        if (len > ADATP_WS_MAX_MESSAGE) { free(message); return false; }

        uint8_t mask[4] = {0};
        if (masked && !wsReadExact(mask, 4, timeoutMs)) { free(message); return false; }

        uint8_t* payload = NULL;
        if (len > 0) {
            payload = (uint8_t*)malloc(len);
            if (!payload) { free(message); return false; }
            if (!wsReadExact(payload, len, timeoutMs)) { free(payload); free(message); return false; }
            if (masked) for (uint32_t i = 0; i < len; i++) payload[i] ^= mask[i % 4];
        }

        switch (opcode) {
            case 0x2: // binary
                free(message);
                message = payload;
                messageLen = len;
                inBinary = true;
                if (fin) { *out = message; *outLen = messageLen; return true; }
                break;
            case 0x0: // continuation
                if (inBinary && payload) {
                    uint8_t* nb = (uint8_t*)realloc(message, messageLen + len);
                    if (!nb) { free(payload); free(message); return false; }
                    message = nb;
                    memcpy(message + messageLen, payload, len);
                    messageLen += len;
                    free(payload);
                    if (fin) { *out = message; *outLen = messageLen; return true; }
                } else {
                    free(payload);
                }
                break;
            case 0x9: // ping → pong
                wsSendFrame(0xA, payload, len);
                free(payload);
                break;
            case 0x8: // close
                wsSendFrame(0x8, NULL, 0);
                free(payload);
                free(message);
                _client.stop();
                return false;
            default: // text / pong / reserved
                free(payload);
                break;
        }
    }
    free(message);
    return false;
}

// -------------------------------------------------------------------------
// PACKET LAYER
// -------------------------------------------------------------------------

bool AdaTP::parseHeader(const uint8_t* buf, PacketHeader& header) {
    header.magic = (uint32_t)buf[0] | ((uint32_t)buf[1]<<8) | ((uint32_t)buf[2]<<16) | ((uint32_t)buf[3]<<24);
    header.version = buf[4];
    header.flags = buf[5] | (buf[6]<<8);
    header.length = (uint32_t)buf[7] | ((uint32_t)buf[8]<<8) | ((uint32_t)buf[9]<<16) | ((uint32_t)buf[10]<<24);
    header.sequence = (uint64_t)buf[11] | ((uint64_t)buf[12]<<8) | ((uint64_t)buf[13]<<16) | ((uint64_t)buf[14]<<24) |
                      ((uint64_t)buf[15]<<32) | ((uint64_t)buf[16]<<40) | ((uint64_t)buf[17]<<48) | ((uint64_t)buf[18]<<56);
    header.msg_type = buf[19] | (buf[20]<<8);
    memcpy(header.session_id, buf+29, 16);
    return header.magic == ADATP_MAGIC;
}

void AdaTP::loop() {
    if (!_client.connected()) {
        if (_connected) {
            _connected = false;
            if (_onDisconnect) _onDisconnect();
        }
        return;
    }

    // A frame header is at least 2 bytes; only start reading when data waits.
    if (_client.available() >= 2) {
        uint8_t* frame = NULL;
        size_t frameLen = 0;
        if (!wsReadMessage(&frame, &frameLen, 2000)) return;
        if (frameLen < 45) { free(frame); return; }

        PacketHeader hdr;
        if (!parseHeader(frame, hdr)) { free(frame); _client.stop(); return; }

        size_t need = 45 + hdr.length + ((hdr.flags & FLAG_ENCRYPTED) ? 16 : 0);
        if (frameLen < need) { free(frame); return; }

        uint8_t* payload = frame + 45;
        const uint8_t* tag = frame + 45 + hdr.length;

        if ((hdr.flags & FLAG_ENCRYPTED) && _secure) {
            if (!crypto_decrypt(payload, hdr.length, tag, payload, hdr.sequence)) {
                free(frame);
                _client.stop();
                return;
            }
            if (hdr.sequence >= _rxSeq) _rxSeq = hdr.sequence + 1;
        }

        if (hdr.msg_type == MSG_TEXT) {
            String txt = "";
            for(size_t i=0; i<hdr.length; i++) txt += (char)payload[i];
            if (_onMessage) _onMessage("Server", txt);
        }

        free(frame);
    }
}

bool AdaTP::connect(const char* host, uint16_t port, const char* username, const char* password,
                    const char* path) {
    if (!_client.connect(host, port)) return false;

    if (!wsHandshake(host, port, path)) {
        _client.stop();
        return false;
    }

    if (!performHandshake(username, password)) {
        _client.stop();
        return false;
    }

    _connected = true;
    if (_onConnect) _onConnect();
    return true;
}

// -------------------------------------------------------------------------
// CRYPTO IMPL (ESP32 mbedTLS)
// -------------------------------------------------------------------------

bool AdaTP::crypto_ecdh_keygen(uint8_t* pub, uint8_t* priv) {
#ifdef ESP32
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ecdh_context ctx;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ecdh_init(&ctx);

    const char* pers = "adatp_gen";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers));

    mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_CURVE25519);
    mbedtls_ecdh_gen_public(&ctx.grp, &ctx.d, &ctx.Q, mbedtls_ctr_drbg_random, &ctr_drbg);

    // Write Public (X25519 uses only X coordinate)
    mbedtls_mpi_write_binary(&ctx.Q.X, pub, 32);
    reverseBytes(pub, 32);

    // Write Private
    mbedtls_mpi_write_binary(&ctx.d, priv, 32);
    reverseBytes(priv, 32);

    mbedtls_ecdh_free(&ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return true;
#else
    // Fallback Mock
    for(int i=0;i<32;i++) { pub[i]=0xAA; priv[i]=0xBB; }
    return true;
#endif
}

bool AdaTP::crypto_ecdh_shared(const uint8_t* peerPub, const uint8_t* myPriv, uint8_t* secret) {
#ifdef ESP32
    mbedtls_ecdh_context ctx;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

    mbedtls_ecdh_init(&ctx);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_CURVE25519);

    // Import My Private Key
    uint8_t revPriv[32]; memcpy(revPriv, myPriv, 32); reverseBytes(revPriv, 32);
    mbedtls_mpi_read_binary(&ctx.d, revPriv, 32); // BE

    // Import Peer Public Key (X coordinate only)
    uint8_t revPub[32]; memcpy(revPub, peerPub, 32); reverseBytes(revPub, 32);
    mbedtls_mpi_read_binary(&ctx.Qp.X, revPub, 32); // BE
    mbedtls_mpi_lset(&ctx.Qp.Z, 1); // Z=1

    mbedtls_mpi z; mbedtls_mpi_init(&z); // Shared Secret Result

    // Calculate Shared Secret (z)
    mbedtls_ecdh_compute_shared(&ctx.grp, &z, &ctx.Qp, &ctx.d, mbedtls_ctr_drbg_random, &ctr_drbg);

    // Output
    mbedtls_mpi_write_binary(&z, secret, 32);
    reverseBytes(secret, 32); // LE

    mbedtls_mpi_free(&z);
    mbedtls_ecdh_free(&ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return true;
#else
    return true;
#endif
}

// Helpers for HMAC-SHA256
void hmac_sha256(const uint8_t* key, size_t keyLen, const uint8_t* data, size_t dataLen, uint8_t* out) {
#ifdef ESP32
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&ctx, key, keyLen);
    mbedtls_md_hmac_update(&ctx, data, dataLen);
    mbedtls_md_hmac_finish(&ctx, out);
    mbedtls_md_free(&ctx);
#endif
}

bool AdaTP::crypto_hkdf(const uint8_t* secret, uint8_t* outKey) {
#ifdef ESP32
    // Implements HKDF-Extract + Expand
    // AdaTP: Salt = 32 bytes of zeros
    uint8_t salt[32] = {0};
    uint8_t prk[32];

    // 1. Extract
    hmac_sha256(salt, 32, secret, 32, prk);

    // 2. Expand ("client_write" -> 32)
    const char* infoCW = "client_write";
    uint8_t bufCW[12 + 1];
    memcpy(bufCW, infoCW, 12); bufCW[12] = 0x01;
    hmac_sha256(prk, 32, bufCW, 13, _clientWriteKey);

    // 3. Expand ("server_write" -> 32)
    const char* infoSW = "server_write";
    uint8_t bufSW[12 + 1];
    memcpy(bufSW, infoSW, 12); bufSW[12] = 0x01;
    hmac_sha256(prk, 32, bufSW, 13, _serverWriteKey);

    // 4. Expand ("client_iv" -> 12), truncate 32 -> 12
    const char* infoCI = "client_iv";
    uint8_t bufCI[9 + 1];
    memcpy(bufCI, infoCI, 9); bufCI[9] = 0x01;
    uint8_t tmp[32];
    hmac_sha256(prk, 32, bufCI, 10, tmp);
    memcpy(_clientIvRoot, tmp, 12);

    // 5. Expand ("server_iv" -> 12)
    const char* infoSI = "server_iv";
    uint8_t bufSI[9 + 1];
    memcpy(bufSI, infoSI, 9); bufSI[9] = 0x01;
    hmac_sha256(prk, 32, bufSI, 10, tmp);
    memcpy(_serverIvRoot, tmp, 12);

    return true;
#else
    return true;
#endif
}

bool AdaTP::crypto_encrypt(const uint8_t* plain, size_t len, uint8_t* cipher, uint8_t* tag, uint64_t seq) {
#ifdef ESP32
    // IV Calculation: Root XOR (LeBytes(Seq) at Offset 4)
    uint8_t iv[12];
    memcpy(iv, _clientIvRoot, 12);
    for(int i=0; i<8; i++) {
        iv[4+i] ^= (uint8_t)((seq >> (i*8)) & 0xFF);
    }

    mbedtls_gcm_setkey(&_gcmCtx, MBEDTLS_CIPHER_ID_AES, _clientWriteKey, 256);
    int ret = mbedtls_gcm_crypt_and_tag(&_gcmCtx, MBEDTLS_GCM_ENCRYPT, len, iv, 12, NULL, 0, plain, cipher, 16, tag);
    return (ret == 0);
#else
    memcpy(cipher, plain, len); return true;
#endif
}

bool AdaTP::crypto_decrypt(const uint8_t* cipher, size_t len, const uint8_t* tag, uint8_t* plain, uint64_t seq) {
#ifdef ESP32
    uint8_t iv[12];
    memcpy(iv, _serverIvRoot, 12);
    for(int i=0; i<8; i++) {
        iv[4+i] ^= (uint8_t)((seq >> (i*8)) & 0xFF);
    }

    mbedtls_gcm_setkey(&_gcmCtx, MBEDTLS_CIPHER_ID_AES, _serverWriteKey, 256);
    int ret = mbedtls_gcm_auth_decrypt(&_gcmCtx, len, iv, 12, NULL, 0, tag, 16, cipher, plain);
    return (ret == 0);
#else
    return true;
#endif
}

// -------------------------------------------------------------------------
// HIGH LEVEL FLOW
// -------------------------------------------------------------------------

bool AdaTP::performHandshake(const char* username, const char* password) {
    _txSeq = 1; _rxSeq = 1;

    uint8_t clientPub[32], clientPriv[32];
    crypto_ecdh_keygen(clientPub, clientPriv);

    sendPacket(MSG_HANDSHAKE_INIT, clientPub, 32);

    // Wait for HANDSHAKE_RESPONSE
    uint8_t* frame = NULL;
    size_t frameLen = 0;
    if (!wsReadMessage(&frame, &frameLen, 5000)) return false;
    if (frameLen < 45 + 32) { free(frame); return false; }

    PacketHeader hdr;
    if (!parseHeader(frame, hdr) || hdr.msg_type != MSG_HANDSHAKE_RESP) { free(frame); return false; }

    uint8_t serverPub[32];
    memcpy(serverPub, frame + 45, 32);
    free(frame);

    // Compute Shared Secret + Session Keys
    crypto_ecdh_shared(serverPub, clientPriv, _sharedSecret);
    crypto_hkdf(_sharedSecret, NULL);
    _secure = true; // Enable Encryption

    // Handshake Complete (Encrypted)
    const char* verifyMsg = "Verification OK";
    sendPacket(MSG_HANDSHAKE_COMP, (uint8_t*)verifyMsg, strlen(verifyMsg), true);

    // Authentication
    String initJson = "{\"username\":\"" + String(username) + "\",\"password\":\"" + String(password) + "\"}";
    sendPacket(MSG_AUTH_REQUEST, (const uint8_t*)initJson.c_str(), initJson.length(), true);

    // Wait for Auth Result
    if (!wsReadMessage(&frame, &frameLen, 5000)) return false;
    if (frameLen < 45) { free(frame); return false; }
    if (!parseHeader(frame, hdr)) { free(frame); return false; }

    size_t need = 45 + hdr.length + ((hdr.flags & FLAG_ENCRYPTED) ? 16 : 0);
    if (frameLen < need) { free(frame); return false; }

    uint8_t* respPayload = frame + 45;
    const uint8_t* tag = frame + 45 + hdr.length;

    bool authOk = false;
    if (hdr.flags & FLAG_ENCRYPTED) {
        // Must decrypt to verify server authenticity (tag check)
        if (crypto_decrypt(respPayload, hdr.length, tag, respPayload, hdr.sequence)) {
             if (hdr.sequence >= _rxSeq) _rxSeq = hdr.sequence + 1;
             if (hdr.msg_type == MSG_AUTH_SUCCESS) authOk = true;
        }
    } else {
        if (hdr.msg_type == MSG_AUTH_SUCCESS) authOk = true;
    }

    free(frame);
    return authOk;
}

void AdaTP::sendPacket(uint16_t type, const uint8_t* payload, size_t len, bool encrypted) {
    bool doEncrypt = encrypted && _secure;
    size_t total = 45 + len + (doEncrypt ? 16 : 0);
    uint8_t* buf = (uint8_t*)malloc(total);
    if (!buf) return;
    memset(buf, 0, 45);

    uint8_t tag[16] = {0};
    if (doEncrypt) {
        // Encrypt directly into the packet buffer.
        if (!crypto_encrypt(payload, len, buf + 45, tag, _txSeq)) { free(buf); return; }
    } else if (len > 0) {
        memcpy(buf + 45, payload, len);
    }

    buf[0] = 0x54; buf[1] = 0x41; buf[2] = 0x44; buf[3] = 0x41; // "ADAT" LE
    buf[4] = 1;
    if (doEncrypt) buf[5] |= 1;

    buf[7] = len & 0xFF;
    buf[8] = (len >> 8) & 0xFF;
    buf[9] = (len >> 16) & 0xFF;
    buf[10]= (len >> 24) & 0xFF;

    uint64_t seq = doEncrypt ? _txSeq : 0;
    for(int i=0;i<8;i++) buf[11+i] = (seq >> (i*8)) & 0xFF;

    buf[19] = type & 0xFF;
    buf[20] = (type >> 8) & 0xFF;

    uint64_t ts = millis();
    for(int i=0;i<8;i++) buf[21+i] = (ts >> (i*8)) & 0xFF;

    memcpy(buf+29, _sessionId, 16);

    if (doEncrypt) {
        memcpy(buf + 45 + len, tag, 16);
        _txSeq++;
    }

    wsSendFrame(0x2, buf, total);
    free(buf);
}

void AdaTP::say(const char* text) {
    sendPacket(MSG_TEXT, (const uint8_t*)text, strlen(text), true);
}

void AdaTP::joinRoom(const char* room) {
    sendPacket(MSG_JOIN_ROOM, (const uint8_t*)room, strlen(room), true);
}

void AdaTP::sendGameState(const char* json) {
    sendPacket(MSG_GAME_STATE, (const uint8_t*)json, strlen(json), true);
}
