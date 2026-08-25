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
