// Sample IoT Firmware for Security Testing
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// VIOLATION 1: Hardcoded API key
const char* API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";

// VIOLATION 2: Hardcoded password
const char* MQTT_PASSWORD = "admin123";

void connect_mqtt() {
    // VIOLATION 3: MQTT without TLS
    char* broker = "mqtt://iot.eclipse.org";
    
    // VIOLATION 4: Insecure random
    int random_val = rand();
    
    // VIOLATION 5: Weak cipher mention
    char cipher[] = "DES";
    
    // VIOLATION 6: Secret leak via printf
    printf("Connecting with API key: %s\n", API_KEY);
    
    // VIOLATION 7: Insecure function
    char buffer[10];
    gets(buffer);
}

void secure_function() {
    // This should pass security checks
    const char* broker = "mqtts://secure.broker.com";
    
    // Secure random (assuming platform provides it)
    // uint32_t random_val = esp_random();
}

int main() {
    connect_mqtt();
    secure_function();
    return 0;
}