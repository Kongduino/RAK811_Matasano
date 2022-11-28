#include "aes.c"
#include <LoRa.h>
#include <LoRandom.h>
#include "Utilities.h"
#include "Matasano.h"

void setup() {
  Serial.begin(115200);
  uint32_t t0 = millis();
  while (!Serial && millis() - t0 < 5000) delay(100);
  delay(1000);
  Serial.println("\nMatasano Start");
  Serial.println(F(" - [SX1276] Initializing ... "));
  delay(1000);
  pinMode(RADIO_XTAL_EN, OUTPUT); //Power LoRa module
  digitalWrite(RADIO_XTAL_EN, HIGH);
  LoRa.setPins(RADIO_NSS, RADIO_RESET, RADIO_DIO_0);
  if (!LoRa.begin(470e6)) {
    Serial.println("Starting LoRa failed!");
    while (1);
  }
  initMatasano();

#ifdef CH_1_1
  Set1Challenge1();
#endif
#ifdef CH_1_2
  Set1Challenge2();
#endif
#ifdef CH_1_3
  Set1Challenge3();
#endif
#ifdef CH_1_4
  Set1Challenge4();
#endif
#ifdef CH_1_5
  Set1Challenge5();
#endif
#ifdef CH_1_6
  Set1Challenge6();
#endif
#ifdef CH_1_7
  Set1Challenge7();
#endif
#ifdef CH_1_8
  Set1Challenge8();
#endif
#ifdef CH_2_9
  Set2Challenge9();
#endif
#ifdef CH_2_10
  Set2Challenge10();
#endif
#ifdef CH_2_11
  Set2Challenge11();
#endif
}

void loop() {
}
