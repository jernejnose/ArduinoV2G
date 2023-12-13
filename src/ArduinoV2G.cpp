// based on https://github.com/SmartEVSE/ESP32-PLC


//#include <qcaSPI/qcaSPI.h>

#include "Arduino.h"
#include "SPI.h"
#include "ArduinoV2G.h"
#include "exi/projectExiConnector.h"
#include "qcaSPI/qcaSPI.h"

uint8_t txbuffer[3164], rxbuffer[3164];
uint8_t modem_state;
uint8_t myMac[6]; // the MAC of the EVSE (derived from the ESP32's MAC).
uint8_t pevMac[6]; // the MAC of the PEV.
uint8_t myModemMac[6]; // our own modem's MAC (this is different from myMAC !). Unused.
uint8_t pevModemMac[6]; // the MAC of the PEV's modem (obtained with GetSwReq). Could this be used to identify the EV?
uint8_t pevRunId[8]; // pev RunId. Received from the PEV in the CM_SLAC_PARAM.REQ message.
uint16_t AvgACVar[58]; // Average AC Variable Field. (used in CM_ATTEN_PROFILE.IND)
uint8_t NMK[16]; // Network Key. Will be initialized with a random key on each session.
uint8_t NID[] = {1, 2, 3, 4, 5, 6, 7}; // a default network ID. MSB bits 6 and 7 need to be 0.
unsigned long SoundsTimer = 0;

uint8_t ModemsFound = 0;
uint8_t ReceivedSounds = 0;
uint8_t EVCCID[6];  // Mac address or ID from the PEV, used in V2G communication
uint8_t EVSOC = 0;  // State Of Charge of the EV, obtained from the 'ContractAuthenticationRequest' message




void randomizeNmk() {
    // randomize the Network Membership Key (NMK)
    for (uint8_t i=0; i<16; i++) NMK[i] = random(256); // NMK 
}

void setNmkAt(uint16_t index) {
    // sets the Network Membership Key (NMK) at a certain position in the transmit buffer
    for (uint8_t i=0; i<16; i++) txbuffer[index+i] = NMK[i]; // NMK 
}

void setNidAt(uint16_t index) {
    // copies the network ID (NID, 7 bytes) into the wished position in the transmit buffer
    for (uint8_t i=0; i<7; i++) txbuffer[index+i] = NID[i];
}

void setMacAt(uint8_t *mac, uint16_t offset) {
    // at offset 0 in the ethernet frame, we have the destination MAC
    // at offset 6 in the ethernet frame, we have the source MAC
    for (uint8_t i=0; i<6; i++) txbuffer[offset+i]=mac[i];
}

void setRunId(uint16_t offset) {
    // at the given offset in the transmit buffer, fill the 8-bytes-RunId.
    for (uint8_t i=0; i<8; i++) txbuffer[offset+i]=pevRunId[i];
}

void setACVarField(uint16_t offset) {
    for (uint8_t i=0; i<58; i++) txbuffer[offset+i]=AvgACVar[i];
}    

uint16_t getManagementMessageType() {
    // calculates the MMTYPE (base value + lower two bits), see Table 11-2 of homeplug spec
    return rxbuffer[16]*256 + rxbuffer[15];
}

uint16_t getFrameType() {
    // returns the Ethernet Frame type
    // 88E1 = HomeplugAV 
    // 86DD = IPv6
    return rxbuffer[12]*256 + rxbuffer[13];
}



void ModemReset() {
    uint16_t reg16;
    Serial.printf("Reset QCA700X Modem. ");
    reg16 = qcaspi_read_register16(SPI_REG_SPI_CONFIG);
    reg16 = reg16 | SPI_INT_CPU_ON;     // Reset QCA700X
    qcaspi_write_register(SPI_REG_SPI_CONFIG, reg16);
}


void composeSetKey() {
    
    memset(txbuffer, 0x00, 60);  // clear buffer
    txbuffer[0]=0x00; // Destination MAC
    txbuffer[1]=0xB0;
    txbuffer[2]=0x52;
    txbuffer[3]=0x00;
    txbuffer[4]=0x00;
    txbuffer[5]=0x01;                
    setMacAt(myMac, 6);  // Source MAC         
    txbuffer[12]=0x88; // Protocol HomeplugAV
    txbuffer[13]=0xE1;
    txbuffer[14]=0x01; // version
    txbuffer[15]=0x08; // CM_SET_KEY.REQ
    txbuffer[16]=0x60; 
    txbuffer[17]=0x00; // frag_index
    txbuffer[18]=0x00; // frag_seqnum
    txbuffer[19]=0x01; // 0 key info type
                     // 20-23 my nonce (0x00 in spec!)
                     // 24-27 your nonce
    txbuffer[28]=0x04; // 9 nw info pid
        
    txbuffer[29]=0x00; // 10 info prn
    txbuffer[30]=0x00; // 11
    txbuffer[31]=0x00; // 12 pmn
    txbuffer[32]=0x00; // 13 CCo capability
    setNidAt(33);    // 14-20 nid  7 bytes from 33 to 39
                     // Network ID to be associated with the key distributed herein.
                     // The 54 LSBs of this field contain the NID (refer to Section 3.4.3.1). The
                     // two MSBs shall be set to 0b00.
    txbuffer[40]=0x01; // NewEKS. Table A.8 01 is NMK.
    setNmkAt(41); 
}

void composeGetSwReq() {
    // GET_SW.REQ request
    memset(txbuffer, 0x00, 60);  // clear buffer
    txbuffer[0]=0xff;  // Destination MAC Broadcast
    txbuffer[1]=0xff;
    txbuffer[2]=0xff;
    txbuffer[3]=0xff;
    txbuffer[4]=0xff;
    txbuffer[5]=0xff;                
    setMacAt(myMac, 6);  // Source MAC         
    txbuffer[12]=0x88; // Protocol HomeplugAV
    txbuffer[13]=0xE1;
    txbuffer[14]=0x00; // version
    txbuffer[15]=0x00; // GET_SW.REQ
    txbuffer[16]=0xA0;  
    txbuffer[17]=0x00; // Vendor OUI
    txbuffer[18]=0xB0;  
    txbuffer[19]=0x52;  
}

void composeSlacParamCnf() {

    memset(txbuffer, 0x00, 60);  // clear txbuffer
    setMacAt(pevMac, 0);  // Destination MAC
    setMacAt(myMac, 6);  // Source MAC
    txbuffer[12]=0x88; // Protocol HomeplugAV
    txbuffer[13]=0xE1;
    txbuffer[14]=0x01; // version
    txbuffer[15]=0x65; // SLAC_PARAM.CNF
    txbuffer[16]=0x60; // 
    txbuffer[17]=0x00; // 2 bytes fragmentation information. 0000 means: unfragmented.
    txbuffer[18]=0x00; // 
    txbuffer[19]=0xff; // 19-24 sound target
    txbuffer[20]=0xff; 
    txbuffer[21]=0xff; 
    txbuffer[22]=0xff; 
    txbuffer[23]=0xff; 
    txbuffer[24]=0xff; 
    txbuffer[25]=0x0A; // sound count
    txbuffer[26]=0x06; // timeout
    txbuffer[27]=0x01; // resptype
    setMacAt(pevMac, 28);  // forwarding_sta, same as PEV MAC, plus 2 bytes 00 00
    txbuffer[34]=0x00; // 
    txbuffer[35]=0x00; // 
    setRunId(36);  // 36 to 43 runid 8 bytes 
    // rest is 00
}

 void composeAttenCharInd() {
    
    memset(txbuffer, 0x00, 130);  // clear txbuffer
    setMacAt(pevMac, 0);  // Destination MAC
    setMacAt(myMac, 6);  // Source MAC
    txbuffer[12]=0x88; // Protocol HomeplugAV
    txbuffer[13]=0xE1;
    txbuffer[14]=0x01; // version
    txbuffer[15]=0x6E; // ATTEN_CHAR.IND
    txbuffer[16]=0x60;  
    txbuffer[17]=0x00; // 2 bytes fragmentation information. 0000 means: unfragmented.
    txbuffer[18]=0x00; // 
    txbuffer[19]=0x00; // apptype
    txbuffer[20]=0x00; // security
    setMacAt(pevMac, 21); // Mac address of the EV Host which initiates the SLAC process
    setRunId(27); // RunId 8 bytes 
    txbuffer[35]=0x00; // 35 - 51 source_id, 17 bytes 0x00 (defined in ISO15118-3 table A.4)
        
    txbuffer[52]=0x00; // 52 - 68 response_id, 17 bytes 0x00. (defined in ISO15118-3 table A.4)
    
    txbuffer[69]=ReceivedSounds; // Number of sounds. 10 in normal case. 
    txbuffer[70]=0x3A; // Number of groups = 58. (defined in ISO15118-3 table A.4)
    setACVarField(71); // 71 to 128: The group attenuation for the 58 announced groups.
 }


void composeSlacMatchCnf() {
    
    memset(txbuffer, 0x00, 109);  // clear txbuffer
    setMacAt(pevMac, 0);  // Destination MAC
    setMacAt(myMac, 6);  // Source MAC
    txbuffer[12]=0x88; // Protocol HomeplugAV
    txbuffer[13]=0xE1;
    txbuffer[14]=0x01; // version
    txbuffer[15]=0x7D; // SLAC_MATCH.CNF
    txbuffer[16]=0x60; // 
    txbuffer[17]=0x00; // 2 bytes fragmentation information. 0000 means: unfragmented.
    txbuffer[18]=0x00; // 
    txbuffer[19]=0x00; // apptype
    txbuffer[20]=0x00; // security
    txbuffer[21]=0x56; // length 2 byte
    txbuffer[22]=0x00;  
                          // 23 - 39: pev_id 17 bytes. All zero.
    setMacAt(pevMac, 40); // Pev Mac address
                          // 46 - 62: evse_id 17 bytes. All zero.
    setMacAt(myMac, 63);  // 63 - 68 evse_mac 
    setRunId(69);         // runid 8 bytes 69-76 run_id.
                          // 77 to 84 reserved 0
    setNidAt(85);         // 85-91 NID. We can nearly freely choose this, but the upper two bits need to be zero
                          // 92 reserved 0                                 
    setNmkAt(93);         // 93 to 108 NMK. We can freely choose this. Normally we should use a random number. 
}        

void composeFactoryDefaults() {

    memset(txbuffer, 0x00, 60);  // clear buffer
    txbuffer[0]=0x00; // Destination MAC
    txbuffer[1]=0xB0;
    txbuffer[2]=0x52;
    txbuffer[3]=0x00;
    txbuffer[4]=0x00;
    txbuffer[5]=0x01;                
    setMacAt(myMac, 6); // Source MAC         
    txbuffer[12]=0x88; // Protocol HomeplugAV
    txbuffer[13]=0xE1;
    txbuffer[14]=0x00; // version
    txbuffer[15]=0x7C; // Load modem Factory Defaults (same as holding GPIO3 low for 15 secs)
    txbuffer[16]=0xA0; 
    txbuffer[17]=0x00; 
    txbuffer[18]=0xB0; 
    txbuffer[19]=0x52; 
}

// Received SLAC messages from the PEV are handled here
void SlacManager(uint16_t rxbytes) {
    uint16_t reg16, mnt, x;

    mnt = getManagementMessageType();
  
  //  Serial.print("[RX] ");
  //  for (x=0; x<rxbytes; x++) Serial.printf("%02x ",rxbuffer[x]);
  //  Serial.printf("\n");

    if (mnt == (CM_SET_KEY + MMTYPE_CNF)) {
        Serial.printf("received SET_KEY.CNF\n");
        if (rxbuffer[19] == 0x01) {
            modem_state = MODEM_CONFIGURED;
            // copy MAC from the EVSE modem to myModemMac. This MAC is not used for communication.
            memcpy(myModemMac, rxbuffer+6, 6);
            Serial.printf("NMK set\n");
        } else Serial.printf("NMK -NOT- set\n");

    } else if (mnt == (CM_SLAC_PARAM + MMTYPE_REQ)) {
        Serial.printf("received CM_SLAC_PARAM.REQ\n");
        // We received a SLAC_PARAM request from the PEV. This is the initiation of a SLAC procedure.
        // We extract the pev MAC from it.
        memcpy(pevMac, rxbuffer+6, 6);
        // extract the RunId from the SlacParamReq, and store it for later use
        memcpy(pevRunId, rxbuffer+21, 8);
        // We are EVSE, we want to answer.
        composeSlacParamCnf();
        qcaspi_write_burst(txbuffer, 60); // Send data to modem
        modem_state = SLAC_PARAM_CNF;
        Serial.printf("transmitting CM_SLAC_PARAM.CNF\n");

    } else if (mnt == (CM_START_ATTEN_CHAR + MMTYPE_IND) && modem_state == SLAC_PARAM_CNF) {
        Serial.printf("received CM_START_ATTEN_CHAR.IND\n");
        SoundsTimer = millis(); // start timer
        memset(AvgACVar, 0x00, 58); // reset averages.
        ReceivedSounds = 0;
        modem_state = MNBC_SOUND;

    } else if (mnt == (CM_MNBC_SOUND + MMTYPE_IND) && modem_state == MNBC_SOUND) { 
        Serial.printf("received CM_MNBC_SOUND.IND\n");
        ReceivedSounds++;

    } else if (mnt == (CM_ATTEN_PROFILE + MMTYPE_IND) && modem_state == MNBC_SOUND) { 
        Serial.printf("received CM_ATTEN_PROFILE.IND\n");
        for (x=0; x<58; x++) AvgACVar[x] += rxbuffer[27+x];
      
        if (ReceivedSounds == 10) {
            Serial.printf("Start Average Calculation\n");
            for (x=0; x<58; x++) AvgACVar[x] = AvgACVar[x] / ReceivedSounds;
        }  

    } else if (mnt == (CM_ATTEN_CHAR + MMTYPE_RSP) && modem_state == ATTEN_CHAR_IND) { 
        Serial.printf("received CM_ATTEN_CHAR.RSP\n");
        // verify pevMac, RunID, and succesful Slac fields
        if (memcmp(pevMac, rxbuffer+21, 6) == 0 && memcmp(pevRunId, rxbuffer+27, 8) == 0 && rxbuffer[69] == 0) {
            Serial.printf("Successful SLAC process\n");
            modem_state = ATTEN_CHAR_RSP;
        } else modem_state = MODEM_CONFIGURED; // probably not correct, should ignore data, and retransmit CM_ATTEN_CHAR.IND

    } else if (mnt == (CM_SLAC_MATCH + MMTYPE_REQ) && modem_state == ATTEN_CHAR_RSP) { 
        Serial.printf("received CM_SLAC_MATCH.REQ\n"); 
        // Verify pevMac, RunID and MVFLength fields
        if (memcmp(pevMac, rxbuffer+40, 6) == 0 && memcmp(pevRunId, rxbuffer+69, 8) == 0 && rxbuffer[21] == 0x3e) {
            composeSlacMatchCnf();
            qcaspi_write_burst(txbuffer, 109); // Send data to modem
            Serial.printf("transmitting CM_SLAC_MATCH.CNF\n");
            modem_state = MODEM_GET_SW_REQ;
        }

    } else if (mnt == (CM_GET_SW + MMTYPE_CNF) && modem_state == MODEM_WAIT_SW) { 
        // Both the local and Pev modem will send their software version.
        // check if the MAC of the modem is the same as our local modem.
        if (memcmp(rxbuffer+6, myModemMac, 6) != 0) { 
            // Store the Pev modem MAC, as long as it is not random, we can use it for identifying the EV (Autocharge / Plug N Charge)
            memcpy(pevModemMac, rxbuffer+6, 6);
        }
        Serial.printf("received GET_SW.CNF\n");
        ModemsFound++;
    }
}



/*
 * --------------------------------------------
 *                    IPv6 
 * --------------------------------------------
 */

const uint8_t broadcastIPv6[16] = { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
/* our link-local IPv6 address. Based on myMac, but with 0xFFFE in the middle, and bit 1 of MSB inverted */
uint8_t SeccIp[16]; 
uint8_t EvccIp[16];
uint16_t evccTcpPort; /* the TCP port number of the car */
uint8_t sourceIp[16];
uint16_t evccPort;
uint16_t seccPort;
uint16_t sourceport;
uint16_t destinationport;
uint16_t udplen;
uint16_t udpsum;
uint8_t NeighborsMac[6];
uint8_t NeighborsIp[16];
uint8_t DiscoveryReqSecurity;
uint8_t DiscoveryReqTransportProtocol;



#define NEXT_UDP 0x11 /* next protocol is UDP */
#define NEXT_ICMPv6 0x3a /* next protocol is ICMPv6 */

#define UDP_PAYLOAD_LEN 100
uint8_t udpPayload[UDP_PAYLOAD_LEN];
uint16_t udpPayloadLen;

#define V2G_FRAME_LEN 100
uint8_t v2gFrameLen;
uint8_t V2GFrame[V2G_FRAME_LEN];

#define UDP_RESPONSE_LEN 100
uint8_t UdpResponseLen;
uint8_t UdpResponse[UDP_RESPONSE_LEN];

#define IP_RESPONSE_LEN 100
uint8_t IpResponseLen;
uint8_t IpResponse[IP_RESPONSE_LEN];

#define PSEUDO_HEADER_LEN 40
uint8_t pseudoHeader[PSEUDO_HEADER_LEN];

void setSeccIp() {
    // Create a link-local Ipv6 address based on myMac (the MAC of the ESP32).
    memset(SeccIp, 0, 16);
    SeccIp[0] = 0xfe;             // Link-local address
    SeccIp[1] = 0x80;
    // byte 2-7 are zero;               
    SeccIp[8] = myMac[0] ^ 2;     // invert bit 1 of MSB
    SeccIp[9] = myMac[1];
    SeccIp[10] = myMac[2];
    SeccIp[11] = 0xff;
    SeccIp[12] = 0xfe;
    SeccIp[13] = myMac[3];
    SeccIp[14] = myMac[4];
    SeccIp[15] = myMac[5];
}


uint16_t calculateUdpAndTcpChecksumForIPv6(uint8_t *UdpOrTcpframe, uint16_t UdpOrTcpframeLen, const uint8_t *ipv6source, const uint8_t *ipv6dest, uint8_t nxt) {
	uint16_t evenFrameLen, i, value16, checksum;
	uint32_t totalSum;
    // Parameters:
    // UdpOrTcpframe: the udp frame or tcp frame, including udp/tcp header and udp/tcp payload
    // ipv6source: the 16 byte IPv6 source address. Must be the same, which is used later for the transmission.
    // ipv6source: the 16 byte IPv6 destination address. Must be the same, which is used later for the transmission.
	// nxt: The next-protocol. 0x11 for UDP, ... for TCP.
	//
    // Goal: construct an array, consisting of a 40-byte-pseudo-ipv6-header, and the udp frame (consisting of udp header and udppayload).
	// For memory efficienty reason, we do NOT copy the pseudoheader and the udp frame together into one new array. Instead, we are using
	// a dedicated pseudo-header-array, and the original udp buffer.
	evenFrameLen = UdpOrTcpframeLen;
	if ((evenFrameLen & 1)!=0) {
        /* if we have an odd buffer length, we need to add a padding byte in the end, because the sum calculation
           will need 16-bit-aligned data. */
		evenFrameLen++;
		UdpOrTcpframe[evenFrameLen-1] = 0; /* Fill the padding byte with zero. */
	}
    memset(pseudoHeader, 0, PSEUDO_HEADER_LEN);
    /* fill the pseudo-ipv6-header */
    for (i=0; i<16; i++) { /* copy 16 bytes IPv6 addresses */
        pseudoHeader[i] = ipv6source[i]; /* IPv6 source address */
        pseudoHeader[16+i] = ipv6dest[i]; /* IPv6 destination address */
	}
    pseudoHeader[32] = 0; // # high byte of the FOUR byte length is always 0
    pseudoHeader[33] = 0; // # 2nd byte of the FOUR byte length is always 0
    pseudoHeader[34] = UdpOrTcpframeLen >> 8; // # 3rd
    pseudoHeader[35] = UdpOrTcpframeLen & 0xFF; // # low byte of the FOUR byte length
    pseudoHeader[36] = 0; // # 3 padding bytes with 0x00
    pseudoHeader[37] = 0;
    pseudoHeader[38] = 0;
    pseudoHeader[39] = nxt; // # the nxt is at the end of the pseudo header
    // pseudo-ipv6-header finished.
    // Run the checksum over the concatenation of the pseudoheader and the buffer.

  
    totalSum = 0;
	for (i=0; i<PSEUDO_HEADER_LEN/2; i++) { // running through the pseudo header, in 2-byte-steps
        value16 = pseudoHeader[2*i] * 256 + pseudoHeader[2*i+1]; // take the current 16-bit-word
        totalSum += value16; // we start with a normal addition of the value to the totalSum
        // But we do not want normal addition, we want a 16 bit one's complement sum,
        // see https://en.wikipedia.org/wiki/User_Datagram_Protocol
        if (totalSum>=65536) { // On each addition, if a carry-out (17th bit) is produced, 
            totalSum-=65536; // swing that 17th carry bit around 
            totalSum+=1; // and add it to the least significant bit of the running total.
		}
	}
	for (i=0; i<evenFrameLen/2; i++) { // running through the udp buffer, in 2-byte-steps
        value16 = UdpOrTcpframe[2*i] * 256 + UdpOrTcpframe[2*i+1]; // take the current 16-bit-word
        totalSum += value16; // we start with a normal addition of the value to the totalSum
        // But we do not want normal addition, we want a 16 bit one's complement sum,
        // see https://en.wikipedia.org/wiki/User_Datagram_Protocol
        if (totalSum>=65536) { // On each addition, if a carry-out (17th bit) is produced, 
            totalSum-=65536; // swing that 17th carry bit around 
            totalSum+=1; // and add it to the least significant bit of the running total.
		}
	}
    // Finally, the sum is then one's complemented to yield the value of the UDP checksum field.
    checksum = (uint16_t) (totalSum ^ 0xffff);
    
    return checksum;
}

void packResponseIntoEthernet() {
    // packs the IP packet into an ethernet packet
    uint8_t i;
    uint16_t EthTxFrameLen;

    EthTxFrameLen = IpResponseLen + 6 + 6 + 2;  // Ethernet header needs 14 bytes:
                                                //  6 bytes destination MAC
                                                //  6 bytes source MAC
                                                //  2 bytes EtherType
    for (i=0; i<6; i++) {       // fill the destination MAC with the source MAC of the received package
        txbuffer[i] = rxbuffer[6+i];
    }    
    setMacAt(myMac,6); // bytes 6 to 11 are the source MAC
    txbuffer[12] = 0x86; // 86dd is IPv6
    txbuffer[13] = 0xdd;
    for (i=0; i<IpResponseLen; i++) {
        txbuffer[14+i] = IpResponse[i];
    }

    qcaspi_write_burst(txbuffer, EthTxFrameLen);    
}

void packResponseIntoIp(void) {
  // # embeds the (SDP) response into the lower-layer-protocol: IP, Ethernet
  uint8_t i;
  uint16_t plen;
  IpResponseLen = UdpResponseLen + 8 + 16 + 16; // # IP6 header needs 40 bytes:
                                              //  #   4 bytes traffic class, flow
                                              //  #   2 bytes destination port
                                              //  #   2 bytes length (incl checksum)
                                              //  #   2 bytes checksum
  IpResponse[0] = 0x60; // # traffic class, flow
  IpResponse[1] = 0; 
  IpResponse[2] = 0;
  IpResponse[3] = 0;
  plen = UdpResponseLen; // length of the payload. Without headers.
  IpResponse[4] = plen >> 8;
  IpResponse[5] = plen & 0xFF;
  IpResponse[6] = 0x11; // next level protocol, 0x11 = UDP in this case
  IpResponse[7] = 0x0A; // hop limit
    for (i=0; i<16; i++) {
    IpResponse[8+i] = SeccIp[i]; // source IP address
    IpResponse[24+i] = EvccIp[i]; // destination IP address
  }
  for (i=0; i<UdpResponseLen; i++) {
    IpResponse[40+i] = UdpResponse[i];
  }            
  packResponseIntoEthernet();
}


void packResponseIntoUdp(void) {
    //# embeds the (SDP) request into the lower-layer-protocol: UDP
    //# Reference: wireshark trace of the ioniq car
    uint8_t i;
    uint16_t lenInclChecksum;
    uint16_t checksum;
    UdpResponseLen = v2gFrameLen + 8; // # UDP header needs 8 bytes:
                                        //           #   2 bytes source port
                                        //           #   2 bytes destination port
                                        //           #   2 bytes length (incl checksum)
                                        //           #   2 bytes checksum
    UdpResponse[0] = 15118 >> 8;
    UdpResponse[1] = 15118  & 0xFF;
    UdpResponse[2] = evccPort >> 8;
    UdpResponse[3] = evccPort & 0xFF;
    
    lenInclChecksum = UdpResponseLen;
    UdpResponse[4] = lenInclChecksum >> 8;
    UdpResponse[5] = lenInclChecksum & 0xFF;
    // checksum will be calculated afterwards
    UdpResponse[6] = 0;
    UdpResponse[7] = 0;
    memcpy(UdpResponse+8, V2GFrame, v2gFrameLen);
    // The content of buffer is ready. We can calculate the checksum. see https://en.wikipedia.org/wiki/User_Datagram_Protocol
    checksum =calculateUdpAndTcpChecksumForIPv6(UdpResponse, UdpResponseLen, SeccIp, EvccIp, NEXT_UDP); 
    UdpResponse[6] = checksum >> 8;
    UdpResponse[7] = checksum & 0xFF;
    packResponseIntoIp();
}


// SECC Discovery Response.
// The response from the charger to the EV, which transfers the IPv6 address of the charger to the car.
void sendSdpResponse() {
    uint8_t i, lenSdp;
    uint8_t SdpPayload[20]; // SDP response has 20 bytes

    memcpy(SdpPayload, SeccIp, 16); // 16 bytes IPv6 address of the charger.
                                    // This IP address is based on the MAC of the ESP32, with 0xfffe in the middle.
    // Here the charger decides, on which port he will listen for the TCP communication.
    // We use port 15118, same as for the SDP. But also dynamically assigned port would be ok.
    // The alpitronics seems to use different ports on different chargers, e.g. 0xC7A7 and 0xC7A6.
    // The ABB Triple and ABB HPC are reporting port 0xD121, but in fact (also?) listening
    // to the port 15118.
    seccPort = 15118;
    SdpPayload[16] = seccPort >> 8; // SECC port high byte.
    SdpPayload[17] = seccPort & 0xff; // SECC port low byte. 
    SdpPayload[18] = 0x10; // security. We only support "no transport layer security, 0x10".
    SdpPayload[19] = 0x00; // transport protocol. We only support "TCP, 0x00".
    
    // add the SDP header
    lenSdp = sizeof(SdpPayload);
    V2GFrame[0] = 0x01; // version
    V2GFrame[1] = 0xfe; // version inverted
    V2GFrame[2] = 0x90; // payload type. 0x9001 is the SDP response message
    V2GFrame[3] = 0x01; // 
    V2GFrame[4] = (lenSdp >> 24) & 0xff; // 4 byte payload length
    V2GFrame[5] = (lenSdp >> 16) & 0xff;
    V2GFrame[6] = (lenSdp >> 8) & 0xff;
    V2GFrame[7] = lenSdp & 0xff;
    memcpy(V2GFrame+8, SdpPayload, lenSdp);         // ToDo: Check lenSdp against buffer size!
    v2gFrameLen = lenSdp + 8;
    packResponseIntoUdp();
}


void evaluateUdpPayload(void) {
    uint16_t v2gptPayloadType;
    uint32_t v2gptPayloadLen;
    uint8_t i;

    if (destinationport == 15118) { // port for the SECC
      if ((udpPayload[0] == 0x01) && (udpPayload[1] == 0xFE)) { //# protocol version 1 and inverted
        // we are the charger, and it is a message from car to charger, lets save the cars IP and port for later use.
        memcpy(EvccIp, sourceIp, 16);
        evccPort = sourceport;  
        //addressManager.setPevIp(EvccIp);

        // it is a V2GTP message                
        // payload is usually: 01 fe 90 00 00 00 00 02 10 00
        v2gptPayloadType = udpPayload[2]*256 + udpPayload[3];
        // 0x8001 EXI encoded V2G message (Will NOT come with UDP. Will come with TCP.)
        // 0x9000 SDP request message (SECC Discovery)
        // 0x9001 SDP response message (SECC response to the EVCC)
        if (v2gptPayloadType == 0x9000) {
            // it is a SDP request from the car to the charger
            Serial.printf("it is a SDP request from the car to the charger\n");
            v2gptPayloadLen = (((uint32_t)udpPayload[4])<<24)  + 
                              (((uint32_t)udpPayload[5])<<16) +
                              (((uint32_t)udpPayload[6])<<8) +
                              udpPayload[7];
            if (v2gptPayloadLen == 2) {
                //# 2 is the only valid length for a SDP request.
                DiscoveryReqSecurity = udpPayload[8]; // normally 0x10 for "no transport layer security". Or 0x00 for "TLS".
                DiscoveryReqTransportProtocol = udpPayload[9]; // normally 0x00 for TCP
                if (DiscoveryReqSecurity != 0x10) {
                    Serial.printf("DiscoveryReqSecurity %u is not supported\n", DiscoveryReqSecurity);
                } else if (DiscoveryReqTransportProtocol != 0x00) {
                    Serial.printf("DiscoveryReqTransportProtocol %u is not supported\n", DiscoveryReqTransportProtocol);
                } else {
                    // This was a valid SDP request. Let's respond, if we are the charger.
                    Serial.printf("Ok, this was a valid SDP request. We are the SECC. Sending SDP response.\n");
                    sendSdpResponse();
                }
            } else {
                Serial.printf("v2gptPayloadLen on SDP request is %u not supported\n", v2gptPayloadLen);
            }
        } else {    
            Serial.printf("v2gptPayloadType %04x not supported\n", v2gptPayloadType);
        }                  
    }
  }                
}

void evaluateNeighborSolicitation(void) {
    uint16_t checksum;
    uint8_t i;
    /* The neighbor discovery protocol is used by the charger to find out the
        relation between MAC and IP. */

    /* We could extract the necessary information from the NeighborSolicitation,
        means the chargers IP and MAC address. But this is not fully necessary:
        - The chargers MAC was already discovered in the SLAC. So we do not need to extract
        it here again. But if we have not done the SLAC, because the modems are already paired,
        then it makes sense to extract the chargers MAC from the Neighbor Solicitation message.
        - For the chargers IPv6, there are two possible cases:
            (A) The charger made the SDP without NeighborDiscovery. This works, if
                we use the pyPlc.py as charger. It does not care for NeighborDiscovery,
                because the SDP is implemented independent of the address resolution of 
                the operating system.
                In this case, we know the chargers IP already from the SDP.
            (B) The charger insists of doing NeighborSolitcitation in the middle of
                SDP. This behavior was observed on Alpitronics. Means, we have the
                following sequence:
                1. car sends SDP request
                2. charger sends NeighborSolicitation
                3. car sends NeighborAdvertisement
                4. charger sends SDP response
                In this case, we need to extract the chargers IP from the NeighborSolicitation,
                otherwise we have to chance to send the correct NeighborAdvertisement. 
                We can do this always, because this does not hurt for case A, address
                is (hopefully) not changing. */
    /* More general approach: In the network there may be more participants than only the charger,
        e.g. a notebook for sniffing. Eeach of it may send a NeighborSolicitation, and we should NOT use the addresses from the
        NeighborSolicitation as addresses of the charger. The chargers address is only determined
        by the SDP. */
        
    /* save the requesters IP. The requesters IP is the source IP on IPv6 level, at byte 22. */
    memcpy(NeighborsIp, rxbuffer+22, 16);
    /* save the requesters MAC. The requesters MAC is the source MAC on Eth level, at byte 6. */
    memcpy(NeighborsMac, rxbuffer+6, 6);
    
    /* send a NeighborAdvertisement as response. */
    // destination MAC = neighbors MAC
    setMacAt(NeighborsMac, 0); // bytes 0 to 5 are the destination MAC	
    // source MAC = my MAC
    setMacAt(myMac, 6); // bytes 6 to 11 are the source MAC
    // Ethertype 86DD
    txbuffer[12] = 0x86; // # 86dd is IPv6
    txbuffer[13] = 0xdd;
    txbuffer[14] = 0x60; // # traffic class, flow
    txbuffer[15] = 0; 
    txbuffer[16] = 0;
    txbuffer[17] = 0;
    // plen
    #define ICMP_LEN 32 /* bytes in the ICMPv6 */
    txbuffer[18] = 0;
    txbuffer[19] = ICMP_LEN;
    txbuffer[20] = NEXT_ICMPv6;
    txbuffer[21] = 0xff;
    // We are the EVSE. So the SeccIp is our own link-local IP address.
    memcpy(txbuffer+22, SeccIp, 16); // source IP address
    memcpy(txbuffer+38, NeighborsIp, 16); // destination IP address
    /* here starts the ICMPv6 */
    txbuffer[54] = 0x88; /* Neighbor Advertisement */
    txbuffer[55] = 0;	
    txbuffer[56] = 0; /* checksum (filled later) */	
    txbuffer[57] = 0;	

    /* Flags */
    txbuffer[58] = 0x60; /* Solicited, override */	
    txbuffer[59] = 0;
    txbuffer[60] = 0;
    txbuffer[61] = 0;

    memcpy(txbuffer+62, SeccIp, 16); /* The own IP address */
    txbuffer[78] = 2; /* Type 2, Link Layer Address */
    txbuffer[79] = 1; /* Length 1, means 8 byte (?) */
    memcpy(txbuffer+80, myMac, 6); /* The own Link Layer (MAC) address */

    checksum = calculateUdpAndTcpChecksumForIPv6(txbuffer+54, ICMP_LEN, SeccIp, NeighborsIp, NEXT_ICMPv6);
    txbuffer[56] = checksum >> 8;
    txbuffer[57] = checksum & 0xFF;
    
    Serial.printf("transmitting Neighbor Advertisement\n");
    /* Length of the NeighborAdvertisement = 86*/
    qcaspi_write_burst(txbuffer, 86);
}


void IPv6Manager(uint16_t rxbytes) {
    uint16_t x;
    uint16_t nextheader; 
    uint8_t icmpv6type; 

    Serial.printf("\n[RX] ");
    for (x=0; x<rxbytes; x++) Serial.printf("%02x",rxbuffer[x]);
    Serial.printf("\n");

    //# The evaluation function for received ipv6 packages.
  
    if (rxbytes > 60) {
        //# extract the source ipv6 address
        memcpy(sourceIp, rxbuffer+22, 16);
        nextheader = rxbuffer[20];
        if (nextheader == 0x11) { //  it is an UDP frame
            Serial.printf("Its a UDP.\n");
            sourceport = rxbuffer[54]*256 + rxbuffer[55];
            destinationport = rxbuffer[56]*256 + rxbuffer[57];
            udplen = rxbuffer[58]*256 + rxbuffer[59];
            udpsum = rxbuffer[60]*256 + rxbuffer[61];

            //# udplen is including 8 bytes header at the begin
            if (udplen>UDP_PAYLOAD_LEN) {
                /* ignore long UDP */
                Serial.printf("Ignoring too long UDP\n");
                return;
            }
            if (udplen>8) {
                udpPayloadLen = udplen-8;
                for (x=0; x<udplen-8; x++) {
                    udpPayload[x] = rxbuffer[62+x];
                }
                evaluateUdpPayload();
            }                      
        }
        if (nextheader == 0x06) { // # it is an TCP frame
            Serial.printf("TCP received\n");
            evaluateTcpPacket();
        }
        if (nextheader == NEXT_ICMPv6) { // it is an ICMPv6 (NeighborSolicitation etc) frame
            Serial.printf("ICMPv6 received\n");
            icmpv6type = rxbuffer[54];
            if (icmpv6type == 0x87) { /* Neighbor Solicitation */
                Serial.printf("Neighbor Solicitation received\n");
                evaluateNeighborSolicitation();
            }
        }
  }

}


/*
 * --------------------------------------------
 *                    TCP 
 * --------------------------------------------
 */

/* Todo: implement a retry strategy, to cover the situation that single packets are lost on the way. */

#define NEXT_TCP 0x06  // the next protocol is TCP

#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10

uint8_t tcpHeaderLen;
#define TCP_PAYLOAD_LEN 200
uint8_t tcpPayloadLen;
uint8_t tcpPayload[TCP_PAYLOAD_LEN];


#define TCP_ACTIVITY_TIMER_START (5*33) /* 5 seconds */
uint16_t tcpActivityTimer;

#define TCP_TRANSMIT_PACKET_LEN 200
uint8_t TcpTransmitPacketLen;
uint8_t TcpTransmitPacket[TCP_TRANSMIT_PACKET_LEN];

#define TCPIP_TRANSMIT_PACKET_LEN 200
uint8_t TcpIpRequestLen;
uint8_t TcpIpRequest[TCPIP_TRANSMIT_PACKET_LEN];

#define TCP_STATE_CLOSED 0
#define TCP_STATE_SYN_ACK 1
#define TCP_STATE_ESTABLISHED 2
#define TCP_RECEIVE_WINDOW 1000 /* number of octets we are able to receive */

uint8_t tcpState = TCP_STATE_CLOSED;
uint32_t TcpSeqNr;
uint32_t TcpAckNr;

#define TCP_RX_DATA_LEN 1000
uint8_t tcp_rxdataLen=0;
uint8_t tcp_rxdata[TCP_RX_DATA_LEN];

#define stateWaitForSupportedApplicationProtocolRequest 0
#define stateWaitForSessionSetupRequest 1
#define stateWaitForServiceDiscoveryRequest 2
#define stateWaitForServicePaymentSelectionRequest 3
#define stateWaitForContractAuthenticationRequest 4
#define stateWaitForChargeParameterDiscoveryRequest 5 
#define stateWaitForCableCheckRequest 6
#define stateWaitForPreChargeRequest 7
#define stateWaitForPowerDeliveryRequest 8

uint8_t fsmState = stateWaitForSupportedApplicationProtocolRequest;



void routeDecoderInputData(void) {
    /* connect the data from the TCP to the exiDecoder */
    /* The TCP receive data consists of two parts: 1. The V2GTP header and 2. the EXI stream.
        The decoder wants only the EXI stream, so we skip the V2GTP header.
        In best case, we would check also the consistency of the V2GTP header here.
    */
    global_streamDec.data = &tcp_rxdata[V2GTP_HEADER_SIZE];
    global_streamDec.size = tcp_rxdataLen - V2GTP_HEADER_SIZE;
    
    /* We have something to decode, this is a good sign that the connection is fine.
        Inform the ConnectionManager that everything is fine. */
    //connMgr_ApplOk();
}


void tcp_transmit(void) {
  //showAsHex(tcpPayload, tcpPayloadLen, "tcp_transmit");
  if (tcpState == TCP_STATE_ESTABLISHED) {  
    //addToTrace("[TCP] sending data");
    tcpHeaderLen = 20; /* 20 bytes normal header, no options */
    if (tcpPayloadLen+tcpHeaderLen < TCP_TRANSMIT_PACKET_LEN) {    
      memcpy(&TcpTransmitPacket[tcpHeaderLen], tcpPayload, tcpPayloadLen);
      tcp_prepareTcpHeader(TCP_FLAG_PSH + TCP_FLAG_ACK); /* data packets are always sent with flags PUSH and ACK. */
      tcp_packRequestIntoIp();
    } else {
      Serial.printf("Error: tcpPayload and header do not fit into TcpTransmitPacket.\n");
    }      
  }  
}


void addV2GTPHeaderAndTransmit(const uint8_t *exiBuffer, uint8_t exiBufferLen) {
    // takes the bytearray with exidata, and adds a header to it, according to the Vehicle-to-Grid-Transport-Protocol
    // V2GTP header has 8 bytes
    // 1 byte protocol version
    // 1 byte protocol version inverted
    // 2 bytes payload type
    // 4 byte payload length
    tcpPayload[0] = 0x01; // version
    tcpPayload[1] = 0xfe; // version inverted
    tcpPayload[2] = 0x80; // payload type. 0x8001 means "EXI data"
    tcpPayload[3] = 0x01; // 
    tcpPayload[4] = (uint8_t)(exiBufferLen >> 24); // length 4 byte.
    tcpPayload[5] = (uint8_t)(exiBufferLen >> 16);
    tcpPayload[6] = (uint8_t)(exiBufferLen >> 8);
    tcpPayload[7] = (uint8_t)exiBufferLen;
    if (exiBufferLen+8 < TCP_PAYLOAD_LEN) {
        memcpy(tcpPayload+8, exiBuffer, exiBufferLen);
        tcpPayloadLen = 8 + exiBufferLen; /* 8 byte V2GTP header, plus the EXI data */
        //log_v("Step3 %d", tcpPayloadLen);
        //showAsHex(tcpPayload, tcpPayloadLen, "tcpPayload");
        tcp_transmit();
    } else {
        Serial.printf("Error: EXI does not fit into tcpPayload.\n");
    }
}


void decodeV2GTP(void) {

    uint16_t arrayLen, i;
    uint8_t strNamespace[50];
    uint8_t SchemaID, n;
    uint16_t NamespaceLen;


    routeDecoderInputData();
    if (fsmState) projectExiConnector_decode_DinExiDocument();      // Decode DIN EXI
    else projectExiConnector_decode_appHandExiDocument();           // Decode Handshake EXI (on first state only)
    tcp_rxdataLen = 0; /* mark the input data as "consumed" */

    if (fsmState == stateWaitForSupportedApplicationProtocolRequest) {

        // Check if we have received the correct message
        if (aphsDoc.supportedAppProtocolReq_isUsed) {
        
            Serial.printf("SupportedApplicationProtocolRequest\n");
            // process data when no errors occured during decoding
            if (g_errn == 0) {
                arrayLen = aphsDoc.supportedAppProtocolReq.AppProtocol.arrayLen;
                Serial.printf("The car supports %u schemas.\n", arrayLen);
            
                // check all schemas for DIN
                for(n=0; n<arrayLen; n++) {
                    memset(strNamespace, 0, sizeof(strNamespace));
                    NamespaceLen = aphsDoc.supportedAppProtocolReq.AppProtocol.array[n].ProtocolNamespace.charactersLen;
                    SchemaID = aphsDoc.supportedAppProtocolReq.AppProtocol.array[n].SchemaID;
                    for (i=0; i< NamespaceLen; i++) {
                        strNamespace[i] = aphsDoc.supportedAppProtocolReq.AppProtocol.array[n].ProtocolNamespace.characters[i];    
                    }
                    Serial.printf("strNameSpace %s SchemaID: %u\n", strNamespace, SchemaID);

                    if (strstr((const char*)strNamespace, ":din:70121:") != NULL) {
                        Serial.printf("Detected DIN\n");
                        projectExiConnector_encode_appHandExiDocument(SchemaID); // test
                        // Send supportedAppProtocolRes to EV
                        addV2GTPHeaderAndTransmit(global_streamEnc.data, global_streamEncPos);
                        fsmState = stateWaitForSessionSetupRequest;
                    }
                }
            }
        }

    } else if (fsmState == stateWaitForSessionSetupRequest) {
        
        // Check if we have received the correct message
        if (dinDocDec.V2G_Message.Body.SessionSetupReq_isUsed) {

            Serial.printf("SessionSetupReqest\n");

            //n = dinDocDec.V2G_Message.Header.SessionID.bytesLen;
            //for (i=0; i< n; i++) {
            //    Serial.printf("%02x", dinDocDec.V2G_Message.Header.SessionID.bytes[i] );
            //}
            n = dinDocDec.V2G_Message.Body.SessionSetupReq.EVCCID.bytesLen;
            if (n>6) n=6;       // out of range check
            Serial.printf("EVCCID=");
            for (i=0; i<n; i++) {
                EVCCID[i]= dinDocDec.V2G_Message.Body.SessionSetupReq.EVCCID.bytes[i];
                Serial.printf("%02x", EVCCID[i] );
            }
            Serial.printf("\n");
            
            sessionId[0] = 1;   // our SessionId is set up here, and used by _prepare_DinExiDocument
            sessionId[1] = 2;   // This SessionID will be used by the EV in future communication
            sessionId[2] = 3;
            sessionId[3] = 4;
            sessionIdLen = 4;

            // Now prepare the 'SessionSetupResponse' message to send back to the EV
            projectExiConnector_prepare_DinExiDocument();
            
            dinDocEnc.V2G_Message.Body.SessionSetupRes_isUsed = 1;
            init_dinSessionSetupResType(&dinDocEnc.V2G_Message.Body.SessionSetupRes);
            dinDocEnc.V2G_Message.Body.SessionSetupRes.ResponseCode = dinresponseCodeType_OK_NewSessionEstablished;
            
            dinDocEnc.V2G_Message.Body.SessionSetupRes.EVSEID.bytes[0] = 0;
            dinDocEnc.V2G_Message.Body.SessionSetupRes.EVSEID.bytesLen = 1;

            // Send SessionSetupResponse to EV
            global_streamEncPos = 0;
            projectExiConnector_encode_DinExiDocument();
            addV2GTPHeaderAndTransmit(global_streamEnc.data, global_streamEncPos);
            fsmState = stateWaitForServiceDiscoveryRequest;
        }    
        
    } else if (fsmState == stateWaitForServiceDiscoveryRequest) {


                
        // Check if we have received the correct message
        if (dinDocDec.V2G_Message.Body.ServiceDiscoveryReq_isUsed) {

            Serial.printf("ServiceDiscoveryReqest\n");
            n = dinDocDec.V2G_Message.Header.SessionID.bytesLen;
            Serial.printf("SessionID:");
            for (i=0; i<n; i++) Serial.printf("%02x", dinDocDec.V2G_Message.Header.SessionID.bytes[i] );
            Serial.printf("\n");
            
            // Now prepare the 'ServiceDiscoveryResponse' message to send back to the EV
            projectExiConnector_prepare_DinExiDocument();
            
            dinDocEnc.V2G_Message.Body.ServiceDiscoveryRes_isUsed = 1;
            init_dinServiceDiscoveryResType(&dinDocEnc.V2G_Message.Body.ServiceDiscoveryRes);
            dinDocEnc.V2G_Message.Body.ServiceDiscoveryRes.ResponseCode = dinresponseCodeType_OK;
            /* the mandatory fields in the ISO are PaymentOptionList and ChargeService.
            But in the DIN, this is different, we find PaymentOptions, ChargeService and optional ServiceList */
            dinDocEnc.V2G_Message.Body.ServiceDiscoveryRes.PaymentOptions.PaymentOption.array[0] = dinpaymentOptionType_ExternalPayment; /* EVSE handles the payment */
            dinDocEnc.V2G_Message.Body.ServiceDiscoveryRes.PaymentOptions.PaymentOption.arrayLen = 1; /* just one single payment option in the table */
            dinDocEnc.V2G_Message.Body.ServiceDiscoveryRes.ChargeService.ServiceTag.ServiceID = 1; /* todo: not clear what this means  */
            //dinDocEnc.V2G_Message.Body.ServiceDiscoveryRes.ChargeService.ServiceTag.ServiceName
            //dinDocEnc.V2G_Message.Body.ServiceDiscoveryRes.ChargeService.ServiceTag.ServiceName_isUsed
            dinDocEnc.V2G_Message.Body.ServiceDiscoveryRes.ChargeService.ServiceTag.ServiceCategory = dinserviceCategoryType_EVCharging;
            //dinDocEnc.V2G_Message.Body.ServiceDiscoveryRes.ChargeService.ServiceTag.ServiceScope
            //dinDocEnc.V2G_Message.Body.ServiceDiscoveryRes.ChargeService.ServiceTag.ServiceScope_isUsed
            dinDocEnc.V2G_Message.Body.ServiceDiscoveryRes.ChargeService.FreeService = 0; /* what ever this means. Just from example. */
            /* dinEVSESupportedEnergyTransferType, e.g.
            dinEVSESupportedEnergyTransferType_DC_combo_core or
            dinEVSESupportedEnergyTransferType_DC_core or
            dinEVSESupportedEnergyTransferType_DC_extended
            dinEVSESupportedEnergyTransferType_AC_single_phase_core.
            DC_extended means "extended pins of an IEC 62196-3 Configuration FF connector", which is
            the normal CCS connector https://en.wikipedia.org/wiki/IEC_62196#FF) */
            dinDocEnc.V2G_Message.Body.ServiceDiscoveryRes.ChargeService.EnergyTransferType = dinEVSESupportedEnergyTransferType_DC_extended;
            
            // Send ServiceDiscoveryResponse to EV
            global_streamEncPos = 0;
            projectExiConnector_encode_DinExiDocument();
            addV2GTPHeaderAndTransmit(global_streamEnc.data, global_streamEncPos);
            fsmState = stateWaitForServicePaymentSelectionRequest;

        }    
     
    } else if (fsmState == stateWaitForServicePaymentSelectionRequest) {

        routeDecoderInputData();
        projectExiConnector_decode_DinExiDocument();      // Decode EXI
        tcp_rxdataLen = 0; /* mark the input data as "consumed" */
                
        // Check if we have received the correct message
        if (dinDocDec.V2G_Message.Body.ServicePaymentSelectionReq_isUsed) {

            Serial.printf("ServicePaymentSelectionReqest\n");

            if (dinDocDec.V2G_Message.Body.ServicePaymentSelectionReq.SelectedPaymentOption == dinpaymentOptionType_ExternalPayment) {
                Serial.printf("OK. External Payment Selected\n");

                // Now prepare the 'ServicePaymentSelectionResponse' message to send back to the EV
                projectExiConnector_prepare_DinExiDocument();
                 
                dinDocEnc.V2G_Message.Body.ServicePaymentSelectionRes_isUsed = 1;
                init_dinServicePaymentSelectionResType(&dinDocEnc.V2G_Message.Body.ServicePaymentSelectionRes);

                dinDocEnc.V2G_Message.Body.ServicePaymentSelectionRes.ResponseCode = dinresponseCodeType_OK;
                
                // Send SessionSetupResponse to EV
                global_streamEncPos = 0;
                projectExiConnector_encode_DinExiDocument();
                addV2GTPHeaderAndTransmit(global_streamEnc.data, global_streamEncPos);
                fsmState = stateWaitForContractAuthenticationRequest;
            }
        }
    } else if (fsmState == stateWaitForContractAuthenticationRequest) {

        routeDecoderInputData();
        projectExiConnector_decode_DinExiDocument();      // Decode EXI
        tcp_rxdataLen = 0; /* mark the input data as "consumed" */
                
        // Check if we have received the correct message
        if (dinDocDec.V2G_Message.Body.ContractAuthenticationReq_isUsed) {

            Serial.printf("ContractAuthenticationRequest\n");

            // Now prepare the 'ContractAuthenticationResponse' message to send back to the EV
            projectExiConnector_prepare_DinExiDocument();
                        
            dinDocEnc.V2G_Message.Body.ContractAuthenticationRes_isUsed = 1;
            // Set Authorisation immediately to 'Finished'.
            dinDocEnc.V2G_Message.Body.ContractAuthenticationRes.EVSEProcessing = dinEVSEProcessingType_Finished;
            init_dinContractAuthenticationResType(&dinDocEnc.V2G_Message.Body.ContractAuthenticationRes);
            
            // Send SessionSetupResponse to EV
            global_streamEncPos = 0;
            projectExiConnector_encode_DinExiDocument();
            addV2GTPHeaderAndTransmit(global_streamEnc.data, global_streamEncPos);
            fsmState = stateWaitForChargeParameterDiscoveryRequest;
        }    

    } else if (fsmState == stateWaitForChargeParameterDiscoveryRequest) {

        routeDecoderInputData();
        projectExiConnector_decode_DinExiDocument();      // Decode EXI
        tcp_rxdataLen = 0; /* mark the input data as "consumed" */
                
        // Check if we have received the correct message
        if (dinDocDec.V2G_Message.Body.ChargeParameterDiscoveryReq_isUsed) {

            Serial.printf("ChargeParameterDiscoveryRequest\n");

            // Read the SOC from the EVRESSOC data
            EVSOC = dinDocDec.V2G_Message.Body.ChargeParameterDiscoveryReq.DC_EVChargeParameter.DC_EVStatus.EVRESSSOC;

            Serial.printf("Current SoC %d%\n", EVSOC);

            // Now prepare the 'ChargeParameterDiscoveryResponse' message to send back to the EV
            projectExiConnector_prepare_DinExiDocument();
            
            dinDocEnc.V2G_Message.Body.ChargeParameterDiscoveryRes_isUsed = 1;   
            init_dinChargeParameterDiscoveryResType(&dinDocEnc.V2G_Message.Body.ChargeParameterDiscoveryRes);
            
            // Send SessionSetupResponse to EV
            global_streamEncPos = 0;
            projectExiConnector_encode_DinExiDocument();
            addV2GTPHeaderAndTransmit(global_streamEnc.data, global_streamEncPos);
            fsmState = stateWaitForCableCheckRequest;

        }    

    }
    
}


void tcp_packRequestIntoEthernet(void) {
    //# packs the IP packet into an ethernet packet
    uint16_t i;
    uint16_t length;        
    
    length = TcpIpRequestLen + 6 + 6 + 2; // # Ethernet header needs 14 bytes:
                                                    // #  6 bytes destination MAC
                                                    // #  6 bytes source MAC
                                                    // #  2 bytes EtherType
    //# fill the destination MAC with the MAC of the charger
    setMacAt(pevMac, 0);
    setMacAt(myMac, 6); // bytes 6 to 11 are the source MAC
    txbuffer[12] = 0x86; // # 86dd is IPv6
    txbuffer[13] = 0xdd;
    memcpy(txbuffer+14, TcpIpRequest, length);
    
    //Serial.print("[TX] ");
    //for(int x=0; x<length; x++) Serial.printf("%02x",txbuffer[x]);
    //Serial.printf("\n\n");

    qcaspi_write_burst(txbuffer, length);
}

void tcp_packRequestIntoIp(void) {
    // # embeds the TCP into the lower-layer-protocol: IP, Ethernet
    uint8_t i;
    uint16_t plen;
    TcpIpRequestLen = TcpTransmitPacketLen + 8 + 16 + 16; // # IP6 header needs 40 bytes:
                                                //  #   4 bytes traffic class, flow
                                                //  #   2 bytes destination port
                                                //  #   2 bytes length (incl checksum)
                                                //  #   2 bytes checksum
    TcpIpRequest[0] = 0x60; // traffic class, flow
    TcpIpRequest[1] = 0x00; 
    TcpIpRequest[2] = 0x00;
    TcpIpRequest[3] = 0x00;
    plen = TcpTransmitPacketLen; // length of the payload. Without headers.
    TcpIpRequest[4] = plen >> 8;
    TcpIpRequest[5] = plen & 0xFF;
    TcpIpRequest[6] = NEXT_TCP; // next level protocol, 0x06 = TCP in this case
    TcpIpRequest[7] = 0x40; // hop limit
    //
    // We are the EVSE. So the PevIp is our own link-local IP address.
    for (i=0; i<16; i++) {
        TcpIpRequest[8+i] = SeccIp[i]; // source IP address
    }            
    for (i=0; i<16; i++) {
        TcpIpRequest[24+i] = EvccIp[i]; // destination IP address
    }
    for (i=0; i<TcpTransmitPacketLen; i++) {
        TcpIpRequest[40+i] = TcpTransmitPacket[i];
    }
    //showAsHex(TcpIpRequest, TcpIpRequestLen, "TcpIpRequest");
    tcp_packRequestIntoEthernet();
}



void tcp_prepareTcpHeader(uint8_t tcpFlag) {
    uint8_t i;
    uint16_t checksum;

    // # TCP header needs at least 24 bytes:
    // 2 bytes source port
    // 2 bytes destination port
    // 4 bytes sequence number
    // 4 bytes ack number
    // 4 bytes DO/RES/Flags/Windowsize
    // 2 bytes checksum
    // 2 bytes urgentPointer
    // n*4 bytes options/fill (empty for the ACK frame and payload frames)
    TcpTransmitPacket[0] = (uint8_t)(seccPort >> 8); /* source port */
    TcpTransmitPacket[1] = (uint8_t)(seccPort);
    TcpTransmitPacket[2] = (uint8_t)(evccTcpPort >> 8); /* destination port */
    TcpTransmitPacket[3] = (uint8_t)(evccTcpPort);

    TcpTransmitPacket[4] = (uint8_t)(TcpSeqNr>>24); /* sequence number */
    TcpTransmitPacket[5] = (uint8_t)(TcpSeqNr>>16);
    TcpTransmitPacket[6] = (uint8_t)(TcpSeqNr>>8);
    TcpTransmitPacket[7] = (uint8_t)(TcpSeqNr);

    TcpTransmitPacket[8] = (uint8_t)(TcpAckNr>>24); /* ack number */
    TcpTransmitPacket[9] = (uint8_t)(TcpAckNr>>16);
    TcpTransmitPacket[10] = (uint8_t)(TcpAckNr>>8);
    TcpTransmitPacket[11] = (uint8_t)(TcpAckNr);
    TcpTransmitPacketLen = tcpHeaderLen + tcpPayloadLen; 
    TcpTransmitPacket[12] = (tcpHeaderLen/4) << 4; /* 70 High-nibble: DataOffset in 4-byte-steps. Low-nibble: Reserved=0. */

    TcpTransmitPacket[13] = tcpFlag; 
    TcpTransmitPacket[14] = (uint8_t)(TCP_RECEIVE_WINDOW>>8);
    TcpTransmitPacket[15] = (uint8_t)(TCP_RECEIVE_WINDOW);

    // checksum will be calculated afterwards
    TcpTransmitPacket[16] = 0;
    TcpTransmitPacket[17] = 0;

    TcpTransmitPacket[18] = 0; /* 16 bit urgentPointer. Always zero in our case. */
    TcpTransmitPacket[19] = 0;

//    TcpTransmitPacket[20] = 0x02; // Options
//    TcpTransmitPacket[21] = 0x04;
//    TcpTransmitPacket[22] = 0x05;
//    TcpTransmitPacket[23] = 0xa0;
    

    checksum = calculateUdpAndTcpChecksumForIPv6(TcpTransmitPacket, TcpTransmitPacketLen, SeccIp, EvccIp, NEXT_TCP); 
    TcpTransmitPacket[16] = (uint8_t)(checksum >> 8);
    TcpTransmitPacket[17] = (uint8_t)(checksum);

    //Serial.printf("Source:%u Dest:%u Seqnr:%08x Acknr:%08x\n", seccPort, evccTcpPort, TcpSeqNr, TcpAckNr);  
}


void tcp_sendFirstAck(void) {
    Serial.printf("[TCP] sending first ACK\n");
    tcpHeaderLen = 20;
    tcpPayloadLen = 0;
    tcp_prepareTcpHeader(TCP_FLAG_ACK | TCP_FLAG_SYN);	
    tcp_packRequestIntoIp();
}

void tcp_sendAck(void) {
   Serial.printf("[TCP] sending ACK\n");
   tcpHeaderLen = 20; /* 20 bytes normal header, no options */
   tcpPayloadLen = 0;   
   tcp_prepareTcpHeader(TCP_FLAG_ACK);	
   tcp_packRequestIntoIp();
}


void evaluateTcpPacket(void) {
    uint8_t flags;
    uint32_t remoteSeqNr;
    uint32_t remoteAckNr;
    uint16_t SourcePort, DestinationPort, pLen, hdrLen, tmpPayloadLen;
        
    /* todo: check the IP addresses, checksum etc */
    //nTcpPacketsReceived++;
    pLen =  rxbuffer[18]*256 + rxbuffer[19]; /* length of the IP payload */
    hdrLen = (rxbuffer[66]>>4) * 4; /* header length in byte */
    if (pLen >= hdrLen) {
        tmpPayloadLen = pLen - hdrLen;
    } else {
        tmpPayloadLen = 0; /* no TCP payload data */
    } 
    //Serial.printf("pLen=%u, hdrLen=%u, Payload=%u\n", pLen, hdrLen, tmpPayloadLen);  
    SourcePort = rxbuffer[54]*256 +  rxbuffer[55];
    DestinationPort = rxbuffer[56]*256 +  rxbuffer[57];
    if (DestinationPort != 15118) {
        Serial.printf("[TCP] wrong port.\n");
        return; /* wrong port */
    }
    //  tcpActivityTimer=TCP_ACTIVITY_TIMER_START;
    remoteSeqNr = 
            (((uint32_t)rxbuffer[58])<<24) +
            (((uint32_t)rxbuffer[59])<<16) +
            (((uint32_t)rxbuffer[60])<<8) +
            (((uint32_t)rxbuffer[61]));
    remoteAckNr = 
            (((uint32_t)rxbuffer[62])<<24) +
            (((uint32_t)rxbuffer[63])<<16) +
            (((uint32_t)rxbuffer[64])<<8) +
            (((uint32_t)rxbuffer[65]));
    //Serial.printf("Source:%u Dest:%u Seqnr:%08x Acknr:%08x flags:%02x\n", SourcePort, DestinationPort, remoteSeqNr, remoteAckNr, flags);        
    flags = rxbuffer[67];
    if (flags == TCP_FLAG_SYN) { /* This is the connection setup reqest from the EV. */
        if (tcpState == TCP_STATE_CLOSED) {
            evccTcpPort = SourcePort; // update the evccTcpPort to the new TCP port
            TcpSeqNr = 0x01020304; // We start with a 'random' sequence nr
            TcpAckNr = remoteSeqNr+1; // The ACK number of our next transmit packet is one more than the received seq number.
            tcpState = TCP_STATE_SYN_ACK;
            tcp_sendFirstAck();
        }
        return;
    }    
    if (flags == TCP_FLAG_ACK && tcpState == TCP_STATE_SYN_ACK) {
        if (remoteAckNr == (TcpSeqNr + 1) ) {
            Serial.printf("-------------- TCP connection established ---------------\n\n");
            tcpState = TCP_STATE_ESTABLISHED;
        }
        return;
    }
    /* It is no connection setup. We can have the following situations here: */
    if (tcpState != TCP_STATE_ESTABLISHED) {
        /* received something while the connection is closed. Just ignore it. */
        Serial.printf("[TCP] ignore, not connected.\n");
        return;    
    } 

    // It can be an ACK, or a data package, or a combination of both. We treat the ACK and the data independent from each other,
    // to treat each combination. 
   if ((tmpPayloadLen>0) && (tmpPayloadLen< TCP_RX_DATA_LEN)) {
        /* This is a data transfer packet. */
        // flag bit PSH should also be set.
        tcp_rxdataLen = tmpPayloadLen;
        TcpAckNr = remoteSeqNr + tcp_rxdataLen; // The ACK number of our next transmit packet is tcp_rxdataLen more than the received seq number.
        TcpSeqNr = remoteAckNr;                 // tcp_rxdatalen will be cleared later.        
        /* rxbuffer[74] is the first payload byte. */
        memcpy(tcp_rxdata, rxbuffer+74, tcp_rxdataLen);  /* provide the received data to the application */
        //     connMgr_TcpOk();
        tcp_sendAck();  // Send Ack, then process data

        decodeV2GTP();
                
        return;
    }

   if (flags & TCP_FLAG_ACK) {
       Serial.printf("This was an ACK\n\n");
       //nTcpPacketsReceived+=1000;
       TcpSeqNr = remoteAckNr; /* The sequence number of our next transmit packet is given by the received ACK number. */      
   }
}



