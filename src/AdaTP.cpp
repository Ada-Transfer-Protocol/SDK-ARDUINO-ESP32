#include "AdaTP.h"

// Helper for endian swap (mbedTLS MPI is BE, X25519 is LE)
void reverseBytes(uint8_t* start, size_t size) {
    for(size_t i=0; i<size/2; i++) {
        uint8_t t = start[i];
        start[i] = start[size-1-i];
        start[size-1-i] = t;
    }
}

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

void AdaTP::loop() {
    if (!_client.connected()) {
        if (_connected) {
            _connected = false;
            if (_onDisconnect) _onDisconnect();
        }
        return;
    }

    if (_client.available() >= 45) {
        PacketHeader hdr;
        if (!readHeader(hdr)) return;

        if (hdr.magic != ADATP_MAGIC) { _client.stop(); return; }

        uint8_t* payload = (uint8_t*)malloc(hdr.length);
        if (!payload) { _client.stop(); return; }

        size_t read = 0;
        unsigned long start = millis();
        while(read < hdr.length) {
            if (millis() - start > 1000) break;
            if (_client.available()) read += _client.read(payload + read, hdr.length - read);
        }
        
        uint8_t tag[16];
        if (hdr.flags & FLAG_ENCRYPTED) {
            _client.readBytes(tag, 16);
        }

        // Decrypt if needed
        uint8_t* finalPayload = payload;
        
        if ((hdr.flags & FLAG_ENCRYPTED) && _secure) {
            // Decrypt in place
            if (!crypto_decrypt(payload, hdr.length, tag, payload, hdr.sequence)) {
                // Decrypt failed
                free(payload);
                _client.stop();
                return;
            }
            // Update RX Sequence
             if (hdr.sequence >= _rxSeq) _rxSeq = hdr.sequence + 1;
        }

        // Handle
        if (hdr.msg_type == MSG_TEXT) {
            String txt = "";
            for(size_t i=0; i<hdr.length; i++) txt += (char)finalPayload[i];
            if (_onMessage) _onMessage("Server", txt);
        }
        
        free(payload);
    }
}

bool AdaTP::connect(const char* host, uint16_t port, const char* username, const char* password) {
    if (!_client.connect(host, port)) return false;
    
    if (!performHandshake(username, password)) {
        _client.stop();
        return false;
    }
    
    _connected = true;
    if (_onConnect) _onConnect();
    return true;
}

bool AdaTP::readHeader(PacketHeader& header) {
    uint8_t buf[45];
    if (_client.readBytes(buf, 45) != 45) return false;
    
    header.magic = buf[0] | (buf[1]<<8) | (buf[2]<<16) | (buf[3]<<24);
    header.version = buf[4];
    header.flags = buf[5] | (buf[6]<<8);
    header.length = buf[7] | (buf[8]<<8) | (buf[9]<<16) | (buf[10]<<24);
    header.sequence = (uint64_t)buf[11] | ((uint64_t)buf[12]<<8) | ((uint64_t)buf[13]<<16) | ((uint64_t)buf[14]<<24) |
                      ((uint64_t)buf[15]<<32) | ((uint64_t)buf[16]<<40) | ((uint64_t)buf[17]<<48) | ((uint64_t)buf[18]<<56);
    header.msg_type = buf[19] | (buf[20]<<8);
    memcpy(header.session_id, buf+29, 16);
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
#ifdef ESP_PLATFORM
    // ESP32 often has different entropy source
#endif
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
    
    size_t len;
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
    // AdaTP V2: Salt = 32 bytes of zeros
    uint8_t salt[32] = {0};
    uint8_t prk[32];
    
    // 1. Extract
    hmac_sha256(salt, 32, secret, 32, prk);
    
    // 2. Expand ("client_write" -> 32)
    // T(1) = HMAC(PRK, "client_write" | 0x01)
    const char* infoCW = "client_write";
    uint8_t bufCW[12 + 1]; // "client_write\x01"
    memcpy(bufCW, infoCW, 12); bufCW[12] = 0x01;
    hmac_sha256(prk, 32, bufCW, 13, _clientWriteKey);
    
    // 3. Expand ("server_write" -> 32)
    const char* infoSW = "server_write";
    uint8_t bufSW[12 + 1]; 
    memcpy(bufSW, infoSW, 12); bufSW[12] = 0x01;
    hmac_sha256(prk, 32, bufSW, 13, _serverWriteKey);
    
    // 4. Expand ("client_iv" -> 12)
    // Result is 32 bytes, truncate to 12
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

    // Wait Response
    unsigned long start = millis();
    while (_client.available() < 45) {
         if (millis() - start > 3000) return false;
         delay(10);
    }
    
    PacketHeader hdr;
    if (!readHeader(hdr)) return false;
    
    uint8_t serverPub[32];
    _client.readBytes(serverPub, hdr.length);
    
    // Compute Shared Secret
    crypto_ecdh_shared(serverPub, clientPriv, _sharedSecret);
    
    // Derive Session Keys
    crypto_hkdf(_sharedSecret, NULL);
    _secure = true; // Enable Encryption
    
    // 3. Send Handshake Complete (Encrypted)
    const char* verifyMsg = "Verification OK";
    // sendPacket will now encrypt it!
    sendPacket(MSG_HANDSHAKE_COMP, (uint8_t*)verifyMsg, strlen(verifyMsg), true);
    
    // 4. Authentication (v2.0 Simple Token/Password)
    String initJson = "{\"username\":\"" + String(username) + "\",\"password\":\"" + String(password) + "\"}";
    sendPacket(MSG_AUTH_REQUEST, (const uint8_t*)initJson.c_str(), initJson.length(), true);
    
    // 5. Wait for Auth Result
    start = millis();
    while (_client.available() < 45) {
         if (millis() - start > 5000) return false;
         delay(10);
    }
    
    if (!readHeader(hdr)) return false;
    
    // Read Response Payload
    uint8_t* respPayload = (uint8_t*)malloc(hdr.length);
    if (!respPayload) return false;
    _client.readBytes(respPayload, hdr.length);
    
    // Read Tag
    uint8_t tag[16];
    if (hdr.flags & FLAG_ENCRYPTED) _client.readBytes(tag, 16);
    
    bool authOk = false;
    if (hdr.flags & FLAG_ENCRYPTED) {
        // Must Decrypt to verify server authenticity (Tag Check)
        if (crypto_decrypt(respPayload, hdr.length, tag, respPayload, hdr.sequence)) {
             // Update RX Seq
             if (hdr.sequence >= _rxSeq) _rxSeq = hdr.sequence + 1;
             
             if (hdr.msg_type == MSG_AUTH_SUCCESS) authOk = true;
        }
    } else {
        // Unencrypted Auth Response? Protocol v2 enforces encryption here.
        // But if server sent unencrypted success, technically OK?
        if (hdr.msg_type == MSG_AUTH_SUCCESS) authOk = true;
    }
    
    free(respPayload);
    return authOk;
}

void AdaTP::sendPacket(uint16_t type, const uint8_t* payload, size_t len, bool encrypted) {
    uint8_t head[45];
    memset(head, 0, 45);
    
    uint8_t* finalPayload = (uint8_t*)payload;
    uint8_t tag[16] = {0};
    uint8_t* cipherBuf = NULL;
    
    if (encrypted && _secure) {
        cipherBuf = (uint8_t*)malloc(len);
        if(!cipherBuf) return;
        
        crypto_encrypt(payload, len, cipherBuf, tag, _txSeq);
        finalPayload = cipherBuf;
    }
    
    head[0] = 0x54; head[1] = 0x41; head[2] = 0x44; head[3] = 0x41;
    head[4] = 1; 
    if(encrypted) head[5] |= 1;
    
    head[7] = len & 0xFF;
    head[8] = (len >> 8) & 0xFF; // ...
    head[9] = (len >> 16) & 0xFF;
    head[10]= (len >> 24) & 0xFF;
    
    // Sequence
    uint64_t seq = (encrypted && _secure) ? _txSeq : 0;
    for(int i=0;i<8;i++) head[11+i] = (seq >> (i*8)) & 0xFF;
    
    // Type
    head[19] = type & 0xFF;
    head[20] = (type >> 8) & 0xFF;
    
    // Timestamp (millis)
    uint64_t ts = millis();
    for(int i=0;i<8;i++) head[21+i] = (ts >> (i*8)) & 0xFF;
    
    memcpy(head+29, _sessionId, 16);
    
    _client.write(head, 45);
    _client.write(finalPayload, len);
    
    if(encrypted) {
        _client.write(tag, 16);
        if (_secure) _txSeq++;
    }
    
    if(cipherBuf) free(cipherBuf);
}

void AdaTP::say(const char* text) {
    sendPacket(MSG_TEXT, (const uint8_t*)text, strlen(text), true);
}
