#include <Arduino.h>
#include <ArduinoV2G.h>
#include <SPI.h>


unsigned long ModemSearchTimer = 0;

// Task
// 
// called every 20ms
//
void Timer20ms(void * parameter) {

    uint16_t reg16, rxbytes, mnt, x;
    uint16_t FrameType;
    
    while(1)  // infinite loop
    {
        switch(modem_state) {
          
            case MODEM_POWERUP:
                Serial.printf("Searching for local modem.. ");
                reg16 = qcaspi_read_register16(SPI_REG_SIGNATURE);
                if (reg16 == QCASPI_GOOD_SIGNATURE) {
                    Serial.printf("QCA700X modem found\n");
                    modem_state = MODEM_WRITESPACE;
                }    
                break;

            case MODEM_WRITESPACE:
                reg16 = qcaspi_read_register16(SPI_REG_WRBUF_SPC_AVA);
                if (reg16 == QCA7K_BUFFER_SIZE) {
                    Serial.printf("QCA700X write space ok\n"); 
                    modem_state = MODEM_CM_SET_KEY_REQ;
                }  
                break;

            case MODEM_CM_SET_KEY_REQ:
                randomizeNmk();       // randomize Nmk, so we start with a new key.
                composeSetKey();      // set up buffer with CM_SET_KEY.REQ request data
                qcaspi_write_burst(txbuffer, 60);    // write minimal 60 bytes according to an4_rev5.pdf
                Serial.printf("transmitting SET_KEY.REQ, to configure the EVSE modem with random NMK\n"); 
                modem_state = MODEM_CM_SET_KEY_CNF;
                break;

            case MODEM_GET_SW_REQ:
                composeGetSwReq();
                qcaspi_write_burst(txbuffer, 60); // Send data to modem
                Serial.printf("Modem Search..\n");
                ModemsFound = 0; 
                ModemSearchTimer = millis();        // start timer
                modem_state = MODEM_WAIT_SW;
                break;

            default:
                // poll modem for data
                reg16 = qcaspi_read_burst(rxbuffer);

                while (reg16) {
                    // we received data, read the length of the first packet.
                    rxbytes = rxbuffer[8] + (rxbuffer[9] << 8);
                    
                    // check if the header exists and a minimum of 60 bytes are available
                    if (rxbuffer[4] == 0xaa && rxbuffer[5] == 0xaa && rxbuffer[6] == 0xaa && rxbuffer[7] == 0xaa && rxbytes >= 60) {
                        // now remove the header, and footer.
                        memcpy(rxbuffer, rxbuffer+12, reg16-14);
                        //Serial.printf("available: %u rxbuffer bytes: %u\n",reg16, rxbytes);
                    
                        FrameType = getFrameType();
                        if (FrameType == FRAME_HOMEPLUG) SlacManager(rxbytes);
                        else if (FrameType == FRAME_IPV6) IPv6Manager(rxbytes);

                        // there might be more data still in the buffer. Check if there is another packet.
                        if ((int16_t)reg16-rxbytes-14 >= 74) {
                            reg16 = reg16-rxbytes-14;
                            // move data forward.
                            memcpy(rxbuffer, rxbuffer+2+rxbytes, reg16);
                        } else reg16 = 0;
                      
                    } else {
                        Serial.printf("Invalid data!\n");
                        ModemReset();
                        modem_state = MODEM_POWERUP;
                    }  
                }
                break;
        }

        // Did the Sound timer expire?
        if (modem_state == MNBC_SOUND && (SoundsTimer + 600) < millis() ) {
            Serial.printf("SOUND timer expired\n");
            // Send CM_ATTEN_CHAR_IND, even if no Sounds were received.
            composeAttenCharInd();
            qcaspi_write_burst(txbuffer, 129); // Send data to modem
            modem_state = ATTEN_CHAR_IND;
            Serial.printf("transmitting CM_ATTEN_CHAR.IND\n");
        }

        if (modem_state == MODEM_WAIT_SW && (ModemSearchTimer + 1000) < millis() ) {
            Serial.printf("MODEM timer expired. ");
            if (ModemsFound >= 2) {
                Serial.printf("Found %u modems. Private network between EVSE and PEV established\n", ModemsFound); 
                
                Serial.printf("PEV MAC: ");
                for(x=0; x<6 ;x++) Serial.printf("%02x", pevMac[x]);
                Serial.printf(" PEV modem MAC: ");
                for(x=0; x<6 ;x++) Serial.printf("%02x", pevModemMac[x]);
                Serial.printf("\n");

                modem_state = MODEM_LINK_READY;
            } else {
                Serial.printf("(re)transmitting MODEM_GET_SW.REQ\n");
                modem_state = MODEM_GET_SW_REQ;
            } 
        }


        // Pause the task for 20ms
        vTaskDelay(20 / portTICK_PERIOD_MS);

    } // while(1)
}    


void setup() {

    pinMode(PIN_QCA700X_CS, OUTPUT);           // SPI_CS QCA7005 
    pinMode(PIN_QCA700X_INT, INPUT);           // SPI_INT QCA7005 
    pinMode(SPI_SCK, OUTPUT);     
    pinMode(SPI_MISO, INPUT);     
    pinMode(SPI_MOSI, OUTPUT);     

    digitalWrite(PIN_QCA700X_CS, HIGH); 

    // configure SPI connection to QCA modem
    SPI.begin(SPI_SCK, SPI_MISO, SPI_MOSI, PIN_QCA700X_CS);
    // SPI mode is MODE3 (Idle = HIGH, clock in on rising edge), we use a 10Mhz SPI clock
    SPI.beginTransaction(SPISettings(10000000, MSBFIRST, SPI_MODE3));
    //attachInterrupt(digitalPinToInterrupt(PIN_QCA700X_INT), SPI_InterruptHandler, RISING);

    Serial.begin(115200);
    Serial.printf("\npowerup\n");

    // Create Task 20ms Timer
    xTaskCreate(
        Timer20ms,      // Function that should be called
        "Timer20ms",    // Name of the task (for debugging)
        3072,           // Stack size (bytes)                              
        NULL,           // Parameter to pass
        1,              // Task priority
        NULL            // Task handle
    );

    
    esp_read_mac(myMac, ESP_MAC_ETH); // select the Ethernet MAC     
    setSeccIp();  // use myMac to create link-local IPv6 address.

    modem_state = MODEM_POWERUP;
   
}

void loop() {

  // Serial.printf("Total heap: %u\n", ESP.getHeapSize());
  //  Serial.printf("Free heap: %u\n", ESP.getFreeHeap());
  //  Serial.printf("Flash Size: %u\n", ESP.getFlashChipSize());
  //  Serial.printf("Total PSRAM: %u\n", ESP.getPsramSize());
  //  Serial.printf("Free PSRAM: %u\n", ESP.getFreePsram());

    delay(1000);
}