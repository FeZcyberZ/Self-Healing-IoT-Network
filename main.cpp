#include <Arduino.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include <Wire.h>
#include <Preferences.h>

#include <Adafruit_BME280.h>
#include <Adafruit_BMP280.h>
#include <BH1750.h>
#include <Adafruit_VL53L0X.h>

// WiFi credentials
static const char* WIFI_SSID = "IoT";
static const char* WIFI_PASS = "YOUR_WIFI_PASSWORD";

// MQTT broker address and port
static const char* MQTT_HOST = "10.42.0.1";
static const uint16_t MQTT_PORT = 1883;

// I2C pin assignments
static const int I2C_SDA = 21;
static const int I2C_SCL = 22;

// How often telemetry and heartbeats are published (ms)
static const uint32_t TELEMETRY_MS = 3000;
static const uint32_t HEARTBEAT_MS = 5000;

// Backoff limits for WiFi reconnection (ms)
static const uint32_t WIFI_BACKOFF_MIN_MS = 1000;
static const uint32_t WIFI_BACKOFF_MAX_MS = 30000;

// Backoff limits for MQTT reconnection (ms)
static const uint32_t MQTT_BACKOFF_MIN_MS = 1000;
static const uint32_t MQTT_BACKOFF_MAX_MS = 30000;

// Whether the node has been quarantined by the behaviour engine
static bool isolated = false;

// Telemetry sequence number
static uint32_t seq = 0;

// Timestamps for rate-limiting publishes
static uint32_t lastTelemetryMs = 0;
static uint32_t lastHeartbeatMs = 0;

// Packet error rate counters
static uint32_t tx_ok = 0;
static uint32_t tx_fail = 0;
static float packet_error_rate = 0.0f;

// Backoff state for WiFi
static uint32_t nextWifiAttemptMs = 0;
static uint32_t wifiBackoffMs = WIFI_BACKOFF_MIN_MS;

// Backoff state for MQTT
static uint32_t nextMqttAttemptMs = 0;
static uint32_t mqttBackoffMs = MQTT_BACKOFF_MIN_MS;

// Node identity and MQTT credentials stored in NVS
Preferences prefs;
static String node_id;
static String mqtt_user;
static String mqtt_pass;

// MQTT topic strings built from node_id at startup
static String topic_status;
static String topic_telemetry;
static String topic_cmd;

// MQTT client
WiFiClient espClient;
PubSubClient mqtt(espClient);

// Sensor objects
Adafruit_BME280 bme;
Adafruit_BMP280 bmp;
BH1750 bh;
Adafruit_VL53L0X vl;

// Flags set at startup depending on which sensors are detected
static bool has_bme = false;
static bool has_bmp = false;
static bool has_bh  = false;
static bool has_vl  = false;

// Load credentials from flash
static void loadNVS() {
  prefs.begin("mesh", true);
  node_id   = prefs.getString("node_id",   "");
  mqtt_user = prefs.getString("mqtt_user", "");
  mqtt_pass = prefs.getString("mqtt_pass", "");
  prefs.end();
}

// Save credentials to flash
static void saveNVS() {
  prefs.begin("mesh", false);
  prefs.putString("node_id",   node_id);
  prefs.putString("mqtt_user", mqtt_user);
  prefs.putString("mqtt_pass", mqtt_pass);
  prefs.end();
}

// Returns true if all required credentials are present
static bool provisioned() {
  return node_id.length() > 0 &&
         mqtt_user.length() > 0 &&
         mqtt_pass.length() > 0;
}

// Read a newline-terminated string from serial
static String readLine() {
  while (!Serial.available()) delay(10);
  String s = Serial.readStringUntil('\n');
  s.trim();
  return s;
}

// Build MQTT topic strings from node_id
static void buildTopics() {
  topic_status    = "mesh/" + node_id + "/status";
  topic_telemetry = "mesh/" + node_id + "/telemetry";
  topic_cmd       = "mesh/" + node_id + "/cmd/state";
}

// Interactive serial prompt to set node_id and MQTT credentials
static void provisionNow() {
  Serial.println("Provision mode");

  Serial.print("node_id (node1..node5): ");
  node_id = readLine();

  Serial.print("mqtt_user: ");
  mqtt_user = readLine();

  Serial.print("mqtt_pass: ");
  mqtt_pass = readLine();

  if (!provisioned()) {
    Serial.println("Missing values; not saving.");
    return;
  }

  saveNVS();
  Serial.println("Saved. Rebooting...");
  delay(750);
  ESP.restart();
}

// Probe I2C bus and initialise whichever sensors are present
static void initSensors() {
  Wire.begin(I2C_SDA, I2C_SCL);
  delay(50);

  has_bme = bme.begin(0x76) || bme.begin(0x77);

  if (!has_bme) {
    has_bmp = bmp.begin(0x76) || bmp.begin(0x77);
  }

  has_bh = bh.begin(BH1750::CONTINUOUS_HIGH_RES_MODE);
  has_vl = vl.begin();

  Serial.printf("Sensors: BME:%d BMP:%d BH:%d VL:%d\n",
                has_bme, has_bmp, has_bh, has_vl);
}

// Publish a plain-text status message to the status topic
static void publishStatus(const char* msg, bool retained = false) {
  if (mqtt.connected()) {
    mqtt.publish(topic_status.c_str(), msg, retained);
  }
}

// Publish a heartbeat so the engine knows the node is alive
static void publishHeartbeat() {
  if (!mqtt.connected()) return;
  publishStatus("HB", false);
}

// Start a WiFi connection attempt
static void wifiKick() {
  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(true);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
}

// Reconnect to WiFi using exponential backoff
static void wifiEnsure() {
  const uint32_t now = millis();

  if (WiFi.status() == WL_CONNECTED) {
    wifiBackoffMs = WIFI_BACKOFF_MIN_MS;
    return;
  }

  if (now < nextWifiAttemptMs) return;

  Serial.println("WiFi: attempting connect");
  wifiKick();

  const uint32_t jitter = (uint32_t)random(0, 250);
  nextWifiAttemptMs = now + wifiBackoffMs + jitter;
  wifiBackoffMs = min(wifiBackoffMs * 2, WIFI_BACKOFF_MAX_MS);
}

// Handle ISOLATE / RESTORE / PING commands from the behaviour engine
static void mqttCallback(char* topic, byte* payload, unsigned int length) {
  String msg;
  msg.reserve(length + 4);

  for (unsigned int i = 0; i < length; i++) {
    msg += (char)payload[i];
  }

  msg.trim();

  if (msg == "ISOLATE") {
    isolated = true;
    publishStatus("QUARANTINED", false);
  } else if (msg == "RESTORE") {
    isolated = false;
    publishStatus("RESTORED", false);
  } else if (msg == "PING") {
    publishStatus("ALIVE", false);
  }
}

// Reconnect to the MQTT broker using exponential backoff
static void mqttEnsure() {
  const uint32_t now = millis();

  if (WiFi.status() != WL_CONNECTED) return;

  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setCallback(mqttCallback);

  if (mqtt.connected()) {
    mqttBackoffMs = MQTT_BACKOFF_MIN_MS;
    return;
  }

  if (now < nextMqttAttemptMs) return;

  Serial.println("MQTT: attempting connect");

  // Connect with last will testament so broker publishes OFFLINE if socket drops
  bool ok = mqtt.connect(
    node_id.c_str(),
    mqtt_user.c_str(),
    mqtt_pass.c_str(),
    topic_status.c_str(),
    1,
    true,
    "OFFLINE"
  );

  if (ok) {
    Serial.println("MQTT: connected");
    mqtt.subscribe(topic_cmd.c_str(), 1);
    publishStatus("ONLINE", true);
  } else {
    Serial.printf("MQTT: failed state=%d\n", mqtt.state());
  }

  const uint32_t jitter = (uint32_t)random(0, 250);
  nextMqttAttemptMs = now + mqttBackoffMs + jitter;
  mqttBackoffMs = min(mqttBackoffMs * 2, MQTT_BACKOFF_MAX_MS);
}

// Read all available sensors and publish a JSON telemetry message
static void publishTelemetry() {
  if (!mqtt.connected()) return;
  if (isolated) return;

  uint32_t uptime_s = millis() / 1000;
  int rssi = (WiFi.status() == WL_CONNECTED) ? WiFi.RSSI() : -127;
  uint32_t heap = ESP.getFreeHeap();
  uint32_t min_heap = ESP.getMinFreeHeap();

  float temp_c    = NAN;
  float press_hpa = NAN;
  float hum_pct   = NAN;
  float lux       = NAN;
  int   range_mm  = -1;

  // Read temperature, pressure and humidity
  if (has_bme) {
    temp_c    = bme.readTemperature();
    press_hpa = bme.readPressure() / 100.0f;
    hum_pct   = bme.readHumidity();
  } else if (has_bmp) {
    temp_c    = bmp.readTemperature();
    press_hpa = bmp.readPressure() / 100.0f;
  }

  // Read ambient light level
  if (has_bh) {
    lux = bh.readLightLevel();
  }

  // Read distance and skip if sensor reports an error
  if (has_vl) {
    VL53L0X_RangingMeasurementData_t m;
    vl.rangingTest(&m, false);
    if (m.RangeStatus != 4) {
      range_mm = m.RangeMilliMeter;
    }
  }

  // Build JSON payload
  char out[512];
  int n = 0;

  n += snprintf(
    out + n,
    sizeof(out) - n,
    "{\"node\":\"%s\",\"seq\":%lu,\"uptime_s\":%lu,"
    "\"rssi\":%d,\"isolated\":%s,"
    "\"heap\":%lu,\"min_heap\":%lu,"
    "\"packet_error_rate\":%.2f",
    node_id.c_str(),
    (unsigned long)seq++,
    (unsigned long)uptime_s,
    rssi,
    isolated ? "true" : "false",
    (unsigned long)heap,
    (unsigned long)min_heap,
    packet_error_rate
  );

  // Append sensor fields only if readings are valid
  if (!isnan(temp_c))    n += snprintf(out + n, sizeof(out) - n, ",\"temp_c\":%.2f",    temp_c);
  if (!isnan(press_hpa)) n += snprintf(out + n, sizeof(out) - n, ",\"press_hpa\":%.2f", press_hpa);
  if (!isnan(hum_pct))   n += snprintf(out + n, sizeof(out) - n, ",\"hum_pct\":%.2f",   hum_pct);
  if (!isnan(lux))       n += snprintf(out + n, sizeof(out) - n, ",\"lux\":%.1f",       lux);
  if (range_mm >= 0)     n += snprintf(out + n, sizeof(out) - n, ",\"range_mm\":%d",    range_mm);

  n += snprintf(out + n, sizeof(out) - n, "}");

  // Abort if buffer overflowed
  if (n < 0 || n >= (int)sizeof(out)) {
    publishStatus("TEL_ERR_TRUNC", false);
    return;
  }

  // Publish and update packet error rate
  bool ok = mqtt.publish(topic_telemetry.c_str(), out, false);

  if (ok) { tx_ok++;   }
  else    { tx_fail++; }

  uint32_t total = tx_ok + tx_fail;
  packet_error_rate = (total > 0) ? ((float)tx_fail / (float)total) : 0.0f;
}

// Arduino setup
void setup() {
  Serial.begin(115200);
  delay(250);
  randomSeed((uint32_t)esp_random());

  loadNVS();

  // Offer a 10 second window to provision if not yet configured
  if (!provisioned()) {
    Serial.println("Not provisioned. Type P within 10 seconds.");
    uint32_t start = millis();

    while (millis() - start < 10000) {
      if (Serial.available()) {
        String s = Serial.readStringUntil('\n');
        s.trim();
        if (s == "P") {
          provisionNow();
        }
      }
      delay(10);
    }

    Serial.println("Provisioning required. Halting.");
    while (1) { delay(1000); }
  }

  buildTopics();
  initSensors();
  wifiKick();
}

// Arduino loop
void loop() {
  wifiEnsure();
  mqttEnsure();

  if (mqtt.connected()) {
    mqtt.loop();
  }

  const uint32_t now = millis();

  // Send heartbeat on schedule
  if (now - lastHeartbeatMs >= HEARTBEAT_MS) {
    lastHeartbeatMs = now;
    publishHeartbeat();
  }

  // Send telemetry on schedule
  if (now - lastTelemetryMs >= TELEMETRY_MS) {
    lastTelemetryMs = now;
    publishTelemetry();
  }
}