/**
 * test3_secure.c - Secure IoT Firmware Example
 * Should pass all security checks with ZERO violations
 */

#include <stdio.h>
#include <stdint.h>
#include "secure_storage.h"
#include "tls_config.h"

// GOOD: Credentials retrieved from secure storage, not hardcoded
const char* get_api_key() {
    return secure_storage_read("api_key");
}

// GOOD: Password from secure provisioning
const char* get_wifi_password() {
    return secure_provisioning_get("wifi_credential");
}

// GOOD: Uses secure random
uint32_t generate_session_id() {
    return esp_random();  // Hardware secure RNG
}

// GOOD: MQTT with TLS and authentication
void connect_to_broker() {
    // Secure connection with TLS
    const char* broker = "mqtts://secure-broker.company.com";
    const char* username = get_api_key();
    const char* password = secure_storage_read("mqtt_password");
    const char* ca_cert = tls_get_ca_certificate();
    
    // Proper authentication
    mqtt_secure_connect(broker, username, password, ca_cert);
}

// GOOD: CoAP with DTLS
void send_coap_message() {
    coaps_send("coaps://secure-sensor.net/data");
    coap_set_dtls_config(DTLS_PSK, get_psk_key());
}

// GOOD: Strong cryptography
void encrypt_data(uint8_t* plaintext, int len, uint8_t* ciphertext) {
    // AES-256-GCM (strong, authenticated encryption)
    aes256_gcm_encrypt(plaintext, len, ciphertext, get_encryption_key());
    
    // SHA-256 for hashing
    sha256_hash(plaintext, len, hash_output);
}

// GOOD: HTTPS with certificate validation
void sync_with_cloud() {
    https_get("https://api.secure-cloud.com/data");
    https_set_certificate_validation(1);  // Verify server cert
    https_set_client_cert(client_cert, client_key);  // Mutual auth
}

// GOOD: Proper error handling
int tls_handshake_secure() {
    int result = tls_connect("secure-server.com", 443);
    if (result < 0) {
        log_error("TLS handshake failed: %d", result);
        return -1;
    }
    
    result = tls_verify_peer();
    if (result != 1) {
        log_error("Certificate validation failed");
        return -1;
    }
    
    return 0;
}

// GOOD: Safe string operations
void process_input(const char* user_input) {
    char buffer[256];
    
    // Safe: fgets with size limit
    fgets(buffer, sizeof(buffer), stdin);
    
    // Safe: snprintf with length limit
    snprintf(buffer, sizeof(buffer), "Processing: %s", user_input);
    
    // Safe: strncpy with null termination
    strncpy(buffer, user_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
}

// GOOD: No secret leaks
void log_status() {
    // Only log non-sensitive information
    printf("Device status: ONLINE\n");
    printf("Firmware version: 2.1.0\n");
    
    // NEVER log credentials or keys
    // secure_logging_redact("Connection established");
}

// GOOD: Proper buffer size checks
void safe_array_operations() {
    int data[100];
    for (int i = 0; i < 100; i++) {  // Bounds check
        data[i] = i;
    }
}

int main() {
    // Initialize secure storage
    secure_storage_init();
    
    // Connect securely
    connect_to_broker();
    send_coap_message();
    
    // Encrypt sensitive data
    uint8_t sensitive[64] = {0};
    uint8_t encrypted[64];
    encrypt_data(sensitive, 64, encrypted);
    
    // Sync with cloud
    sync_with_cloud();
    
    printf("Secure IoT device running safely.\n");
    return 0;
}