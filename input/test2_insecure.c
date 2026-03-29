/**
 * test2_insecure.c - Complex Insecure IoT Firmware
 * Contains multiple security violations for testing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// VIOLATION 1: Hardcoded AWS credentials
const char* AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
const char* AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// VIOLATION 2: Hardcoded JWT token
const char* JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

// VIOLATION 3: Hardcoded database password
const char* DB_PASSWORD = "MyDatabasePass123!";

// VIOLATION 4: Private key embedded
const char* PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";

// Insecure function with buffer overflow
void insecure_network_handler(char* input) {
    char buffer[64];
    char secret_buffer[256];
    
    // VIOLATION 5: strcpy without bounds check
    strcpy(buffer, input);
    
    // VIOLATION 6: sprintf without length limit
    sprintf(secret_buffer, "Processing: %s", input);
    
    // VIOLATION 7: gets() - extremely dangerous
    char user_input[100];
    gets(user_input);
}

// MQTT without TLS and authentication
void publish_sensor_data(int temperature, int humidity) {
    // VIOLATION 8: MQTT without TLS
    char* broker = "mqtt://broker.emqx.io";
    
    // VIOLATION 9: No authentication
    mqtt_connect(broker);
    
    // VIOLATION 10: Hardcoded topic (should be configurable)
    mqtt_publish("sensors/temperature", &temperature);
    
    // VIOLATION 11: Publishing sensitive data
    char* device_id = "DEV-001";
    mqtt_publish("devices/identity", device_id);
}

// CoAP without DTLS
void coap_request_handler() {
    // VIOLATION 12: CoAP without DTLS
    coap_send("coap://sensor-network.local/data");
    
    // VIOLATION 13: Missing authentication
    coap_set_option("no_auth");
}

// Weak cryptography usage
void encrypt_sensitive_data(uint8_t* data, int len) {
    // VIOLATION 14: MD5 hash (broken)
    MD5(data, len, hash_output);
    
    // VIOLATION 15: DES encryption (weak)
    DES_key_schedule key;
    DES_set_key(&key_schedule, &key);
    
    // VIOLATION 16: RC4 stream cipher (broken)
    RC4(key, data, len, output);
    
    // VIOLATION 17: Weak random for IV
    srand(time(NULL));
    int iv = rand();
}

// Secret leak through printf
void log_connection_status() {
    // VIOLATION 18: Printing secret credentials
    printf("Connecting with AWS Key: %s\n", AWS_ACCESS_KEY_ID);
    printf("Using JWT: %s\n", JWT_TOKEN);
    
    // VIOLATION 19: Printing sensitive data to debug log
    fprintf(stderr, "DB Password: %s\n", DB_PASSWORD);
}

// HTTP instead of HTTPS
void cloud_sync() {
    // VIOLATION 20: HTTP without TLS
    http_get("http://api.iot-cloud.com/data");
    http_post("http://api.iot-cloud.com/upload", payload);
}

// Missing error handling for crypto operations
void tls_handshake_insecure() {
    // VIOLATION 21: No error check
    tls_connect("server.com", 443);
    
    // VIOLATION 22: No certificate verification
    tls_set_verify(0);  // Disables verification!
    
    // VIOLATION 23: Sending data without checking connection
    tls_send(sensitive_data);
}

int main() {
    printf("Starting insecure IoT device...\n");
    
    insecure_network_handler("test input");
    publish_sensor_data(25, 60);
    coap_request_handler();
    log_connection_status();
    cloud_sync();
    
    return 0;
}