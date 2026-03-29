#!/usr/bin/env python3
"""
Week 11 Deliverable: Security Test Suite with Assertions
Tests representative IoT firmware patterns (Contiki-NG / Zephyr style).
Each test has an EXPECTED verdict — mismatches are flagged as test failures.
"""

import sys, os, traceback
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compiler.lexer        import Lexer
from compiler.semantic     import SemanticAnalyzer
from compiler.dataflow     import DataFlowAnalyzer
from compiler.policy       import PolicyEngine
from compiler.symbol_table import SymbolTable
from compiler.parser       import Parser

# ── Test definitions ──────────────────────────────────────────────────────────
# Each entry: (name, code, expected_min_issues, expected_verdict)
# expected_verdict: "FAIL" if issues > 0, "PASS" if issues == 0

TEST_CASES = [

    # ── 1. Contiki-NG style: temperature sensor with hardcoded credentials ───
    ("contiki_temp_sensor_insecure",
     """\
/* Contiki-NG temperature sensor - INSECURE */
#include "contiki.h"
#include "net/ipv6/uip.h"

static const char* CLOUD_API_KEY = "sk_live_4eC39HqLyjWD";
static const char* DEVICE_PASSWORD = "admin123";

PROCESS(temp_sensor, "Temp Sensor");
AUTOSTART_PROCESSES(&temp_sensor);

PROCESS_THREAD(temp_sensor, ev, data) {
  PROCESS_BEGIN();
  char buffer[16];
  gets(buffer);
  mqtt_connect("mqtt://cloud.contiki.org");
  int r = rand();
  printf("Key: %s\\n", CLOUD_API_KEY);
  PROCESS_END();
}
""",
     3, "FAIL"),   # expects >=3 issues

    # ── 2. Contiki-NG style: secure light node ───────────────────────────────
    ("contiki_light_node_secure",
     """\
/* Contiki-NG light node - SECURE */
#include "contiki.h"
#include "secure_storage.h"
#include "tls_config.h"

PROCESS(light_node, "Light Node");
AUTOSTART_PROCESSES(&light_node);

PROCESS_THREAD(light_node, ev, data) {
  PROCESS_BEGIN();
  const char* creds = secure_storage_read("mqtt_cred");
  const char* broker = "mqtts://secure-broker.contiki.org";
  uint32_t nonce = esp_random();
  mqtt_secure_connect(broker, creds);
  printf("Light node online.\\n");
  PROCESS_END();
}
""",
     0, "PASS"),

    # ── 3. Zephyr style: MQTT gateway with weak crypto ───────────────────────
    ("zephyr_mqtt_gateway_weak_crypto",
     """\
/* Zephyr RTOS MQTT gateway - weak crypto */
#include <zephyr/kernel.h>
#include <zephyr/net/mqtt.h>

static uint8_t session_key[] = "hardkey12345678!";

void mqtt_gateway_init(void) {
    MD5(session_key, 16, NULL);
    DES_encrypt(session_key);

    char broker_url[] = "mqtt://mqtt.zephyrproject.org";
    mqtt_connect(broker_url);
}

int main(void) {
    mqtt_gateway_init();
    return 0;
}
""",
     2, "FAIL"),

    # ── 4. Zephyr style: CoAP sensor without DTLS ────────────────────────────
    ("zephyr_coap_sensor_no_dtls",
     """\
/* Zephyr CoAP sensor - missing DTLS */
#include <zephyr/net/coap.h>

void coap_sensor_send(int temperature) {
    coap_send("coap://sensors.zephyr.local/temp");
    coap_set_option("no_auth");

    char buf[8];
    sprintf(buf, "%d", temperature);

    http_get("http://dashboard.local/update");
}

int main(void) {
    coap_sensor_send(25);
    return 0;
}
""",
     3, "FAIL"),

    # ── 5. ESP-IDF style: OTA update with credential leak ────────────────────
    ("esp_idf_ota_credential_leak",
     """\
/* ESP-IDF OTA update handler - credential leak */
#include "esp_ota_ops.h"

const char* OTA_SERVER_TOKEN = "Bearer eyJhbGciOiJIUzI1NiJ9.ota_token_xyz";
const char* AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

void ota_check_update(void) {
    printf("Connecting with token: %s\\n", OTA_SERVER_TOKEN);
    fprintf(stderr, "AWS Key: %s\\n", AWS_KEY);
    http_get("http://ota.espressif.com/firmware.bin");
    char* tls_verify = "0";
}

int main(void) {
    ota_check_update();
    return 0;
}
""",
     4, "FAIL"),

    # ── 6. ESP-IDF style: secure provisioning ────────────────────────────────
    ("esp_idf_secure_provisioning",
     """\
/* ESP-IDF secure provisioning - SECURE */
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "esp_random.h"

void provision_device(void) {
    /* Read credentials from NVS (secure storage) */
    const char* ssid = nvs_read_string("wifi_ssid");
    const char* pass = nvs_read_string("wifi_pass");

    uint32_t device_id = esp_random();
    const char* broker = "mqtts://iot.espressif.com";
    mqtt_secure_connect(broker, ssid, pass);
    printf("Device provisioned.\\n");
}

int main(void) {
    nvs_flash_init();
    provision_device();
    return 0;
}
""",
     0, "PASS"),

    # ── 7. Bare-metal: buffer overflow risk ──────────────────────────────────
    ("baremetal_buffer_overflow",
     """\
/* Bare-metal firmware - buffer overflow */
#include <string.h>
#include <stdio.h>

char global_buf[32];
const char* DEVICE_SECRET = "supersecret_device_key_12345";

void handle_command(char* input) {
    strcpy(global_buf, input);
    printf("Cmd: %s secret=%s\\n", global_buf, DEVICE_SECRET);
}

int main(void) {
    char cmd[256];
    gets(cmd);
    handle_command(cmd);
    return 0;
}
""",
     3, "FAIL"),

    # ── 8. Full secure firmware (should produce zero issues) ─────────────────
    ("reference_secure_firmware",
     """\
/* Reference secure IoT firmware */
#include <stdio.h>
#include <stdint.h>
#include "secure_storage.h"
#include "tls_config.h"

void connect_mqtt(void) {
    const char* broker   = "mqtts://secure.iot-broker.com";
    const char* username = secure_storage_read("mqtt_user");
    const char* password = secure_storage_read("mqtt_pass");
    const char* ca_cert  = tls_get_ca_certificate();
    mqtt_secure_connect(broker, username, password, ca_cert);
}

void send_reading(int val) {
    char buf[64];
    snprintf(buf, sizeof(buf), "temp=%d", val);
    mqtt_publish("sensors/temperature", buf);
    printf("Device status: OK\\n");
}

int main(void) {
    secure_storage_init();
    connect_mqtt();
    send_reading(25);
    return 0;
}
""",
     0, "PASS"),
]

# ── Test runner ───────────────────────────────────────────────────────────────

def run_test(name, code, expected_min_issues, expected_verdict):
    result = {
        "name": name,
        "expected_verdict": expected_verdict,
        "actual_verdict": None,
        "issues_found": 0,
        "test_passed": False,
        "error": None,
    }

    try:
        lexer   = Lexer(code)
        tokens  = lexer.tokenize()
        secrets = lexer.detect_secrets()
        ins_fn  = lexer.detect_insecure_functions()
        weak_r  = lexer.detect_weak_random()

        ast = Parser(tokens).parse()
        sym = SymbolTable()

        sem_i = SemanticAnalyzer(code, sym).analyze()
        df_i  = DataFlowAnalyzer(code, sym).detect_leaks()
        pol_i = PolicyEngine(code, sym, ast).enforce()

        total = len(secrets)+len(ins_fn)+len(weak_r)+len(sem_i)+len(df_i)+len(pol_i)
        actual_verdict = "PASS" if total == 0 else "FAIL"

        result["issues_found"]    = total
        result["actual_verdict"]  = actual_verdict
        # Test passes if: actual verdict matches expected AND issue count >= expected minimum
        verdict_ok  = actual_verdict == expected_verdict
        count_ok    = (expected_min_issues == 0 and total == 0) or (total >= expected_min_issues)
        result["test_passed"] = verdict_ok and count_ok

    except Exception as e:
        result["error"]          = str(e)
        result["actual_verdict"] = "ERROR"
        result["test_passed"]    = False

    return result


def main():
    print("=" * 70)
    print("WEEK 11 DELIVERABLE: IoT Security Test Suite")
    print("=" * 70)
    print("Testing 8 representative firmware samples")
    print("(Contiki-NG / Zephyr / ESP-IDF / Bare-metal patterns)\n")

    all_results = []
    for (name, code, exp_min, exp_verdict) in TEST_CASES:
        r = run_test(name, code, exp_min, exp_verdict)
        all_results.append(r)

        # Per-test output
        symbol  = "✅" if r["test_passed"] else "❌"
        verdict = r["actual_verdict"] or "ERROR"
        issues  = r["issues_found"]
        mismatch = "" if r["test_passed"] else f"  ← expected {exp_verdict}"
        print(f"  {symbol} {name}")
        print(f"       Issues: {issues}  |  Verdict: {verdict}{mismatch}")
        if r["error"]:
            print(f"       ERROR: {r['error'][:80]}")
        print()

    # Summary
    passed     = sum(1 for r in all_results if r["test_passed"])
    failed     = len(all_results) - passed
    total_iss  = sum(r["issues_found"] for r in all_results)

    print("=" * 70)
    print("TEST SUITE SUMMARY")
    print("=" * 70)
    print(f"\n  Total tests   : {len(all_results)}")
    print(f"  Passed        : {passed}")
    print(f"  Failed        : {failed}")
    print(f"  Pass rate     : {passed/len(all_results)*100:.1f}%")
    print(f"  Issues found  : {total_iss} across all firmware samples")

    print("\n[TEST COVERAGE]")
    print("  ✓ Hardcoded secret / credential detection")
    print("  ✓ Insecure function detection (gets, strcpy, sprintf)")
    print("  ✓ Weak random number generator detection")
    print("  ✓ MQTT without TLS enforcement")
    print("  ✓ CoAP without DTLS enforcement")
    print("  ✓ HTTP (unencrypted) usage detection")
    print("  ✓ Weak crypto (MD5, DES) detection")
    print("  ✓ Secret data leaked via printf/fprintf")
    print("  ✓ Secure firmware correctly given PASS verdict")

    print("\n[ASSERTION-BASED VALIDATION]")
    print("  Each test has an expected verdict (PASS/FAIL).")
    print("  A test PASSES only when actual == expected.")
    for r in all_results:
        sym = "✅" if r["test_passed"] else "❌"
        print(f"  {sym} {r['name']}: expected={r['expected_verdict']} "
              f"actual={r['actual_verdict']} issues={r['issues_found']}")

    print("\n" + "=" * 70)
    if failed == 0:
        print("✅ WEEK 11 DELIVERABLE COMPLETE — All tests passed assertions.")
    else:
        print(f"⚠️  WEEK 11 DELIVERABLE: {failed} test(s) did not match expected verdict.")
    print("=" * 70)

    return all_results   # importable by week13

if __name__ == "__main__":
    main()