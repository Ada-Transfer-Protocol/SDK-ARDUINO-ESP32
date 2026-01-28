/*
  AdaTP ESP32 Connect Example
  
  This example demonstrates how to connect an ESP32 to the AdaTP Server.
  It listens for "LED_ON" and "LED_OFF" commands to control the built-in LED.
*/

#include <WiFi.h>
#include <AdaTP.h>

// --- CONFIGURATION ---
const char* ssid     = "YOUR_WIFI_SSID";
const char* password = "YOUR_WIFI_PASSWORD";
const char* host     = "192.168.1.10"; // AdaTP Server IP
const uint16_t port  = 8444;           // Default TCP Port

WiFiClient wifiClient;
AdaTP client(wifiClient);

// --- CALLBACKS ---

void onConnected() {
  Serial.println("✅ Connected to AdaTP Server");
  client.say("ESP32 Device Online");
}

void onDisconnect() {
  Serial.println("❌ Disconnected");
}

void onMessage(String from, String msg) {
  Serial.print("Received from "); Serial.print(from); Serial.print(": "); Serial.println(msg);
  
  if (msg == "LED_ON") {
    digitalWrite(2, HIGH);
    client.say("OK: LED turned ON");
  } 
  else if (msg == "LED_OFF") {
    digitalWrite(2, LOW);
    client.say("OK: LED turned OFF");
  }
  else if (msg == "PING") {
    client.say("PONG");
  }
}

// --- MAIN ---

void setup() {
  Serial.begin(115200);
  pinMode(2, OUTPUT);

  // 1. Connect WiFi
  Serial.print("Connecting to WiFi");
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println(" OK");

  // 2. Setup AdaTP
  client.onConnect(onConnected);
  client.onDisconnect(onDisconnect);
  client.onMessage(onMessage);

  // 3. Connect to Server
  Serial.print("Connecting to Server...");
  if (!client.connect(host, port, "esp32_device", "secret")) {
     Serial.println(" Failed!");
  }
}

void loop() {
  client.loop();
  
  // Reconnect logic could go here
  if (!client.isConnected()) {
    // try reconnecting every 10s...
  }
}
