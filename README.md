# AdaTP SDK for Arduino (ESP32/ESP8266)

An official, high-performance C++ SDK for connecting ESP32 and ESP8266 devices to the **Ada Transfer Protocol (AdaTP)** network.

## Features

- **Full Protocol Support**: AdaTP v1.0 over WebSocket (/ws) with the X25519 secure handshake.
- **Hardware Verified Crypto**: Uses native `mbedtls` for hardware-accelerated AES-GCM and X25519 (on supported chips).
- **Secure**:
  - **X25519** ECDH Key Exchange.
  - **AES-256-GCM** Authenticated Encryption.
  - **HKDF** SHA-256 Key Derivation.
  - Replay Protection (Sequence Numbers).
- **Lightweight**: Optimized for embedded systems with minimal allocation overhead.

## Protocol v2 (authenticated handshake) — status

This SDK implements the **v1** handshake (unauthenticated X25519), which relies
on TLS at the edge for server authentication. AdaTP **protocol v2** adds an
Ed25519-signed, key-pinned handshake that resists an active man-in-the-middle
**without** TLS — exactly the case that matters for a field device.

v2 is **not yet implemented here** for one concrete reason: it needs **Ed25519
signature verification**, and the stock ESP32 `mbedtls` build ships **no EdDSA**.
Adding v2 therefore requires bundling a small Ed25519 verify (e.g. a `ref10`
port) and validating it on-device. That work is planned but not shipped —
deliberately not merged unverified. The server and the Node/C/Python/PHP SDKs
already speak v2 end-to-end; see
[the spec](https://github.com/Ada-Transfer-Protocol/Server/blob/main/docs/spec/12-authenticated-handshake.md).
Until then, use `wss://` (TLS) for authentication.

## Requirements

- **Hardware**: ESP32 (Recommended) or ESP8266.
- **Software**: Arduino IDE or PlatformIO.
- **Dependencies**: None (Uses built-in `WiFi` and `mbedtls` libraries).

## Installation

### PlatformIO
Add to `platformio.ini`:
```ini
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino
lib_deps =
    https://github.com/Ada-Transfer-Protocol/SDK-ARDUINO-ESP32.git
```

### Arduino IDE
1. Download this repository as ZIP.
2. Sketch -> Include Library -> Add .ZIP Library.

## Usage

```cpp
#include <WiFi.h>
#include <AdaTP.h>

WiFiClient wifi;
AdaTP client(wifi);

void setup() {
  Serial.begin(115200);
  WiFi.begin("SSID", "PASS");
  
  // Connect securely (performs Handshake + Auth)
  if (client.connect("192.168.1.50", 3000, "device_01", "my_secret_token")) {
    Serial.println("Connected Securely!");
    client.say("Hello World");
  }
}

void loop() {
  client.loop(); // Must be called frequently
}
```

## Security Note for ESP8266
ESP8266 support uses the same `mbedtls` stack but may be slower due to software crypto. For high-throughput applications, **ESP32** is strongly recommended.

## License
MIT

## Language / locale

Set the SDK language for user-facing strings (client-side metadata — the
wire protocol is language-neutral). Default `en`; supported:
`en tr it fr de zh ja hi ar`.

```cpp
AdaTP adatp(wifiClient);
adatp.setLocale("tr");
```
