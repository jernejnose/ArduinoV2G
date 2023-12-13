#include <qcaSPI/qcaSPI.h>


/* SLAC commands */

#define CM_SET_KEY 0x6008
#define CM_GET_KEY 0x600C
#define CM_SC_JOIN 0x6010
#define CM_CHAN_EST 0x6014
#define CM_TM_UPDATE 0x6018
#define CM_AMP_MAP 0x601C
#define CM_BRG_INFO 0x6020
#define CM_CONN_NEW 0x6024
#define CM_CONN_REL 0x6028
#define CM_CONN_MOD 0x602C
#define CM_CONN_INFO 0x6030
#define CM_STA_CAP 0x6034
#define CM_NW_INFO 0x6038
#define CM_GET_BEACON 0x603C
#define CM_HFID 0x6040
#define CM_MME_ERROR 0x6044
#define CM_NW_STATS 0x6048
#define CM_SLAC_PARAM 0x6064
#define CM_START_ATTEN_CHAR 0x6068
#define CM_ATTEN_CHAR 0x606C
#define CM_PKCS_CERT 0x6070
#define CM_MNBC_SOUND 0x6074
#define CM_VALIDATE 0x6078
#define CM_SLAC_MATCH 0x607C
#define CM_SLAC_USER_DATA 0x6080
#define CM_ATTEN_PROFILE 0x6084
#define CM_GET_SW 0xA000

#define MMTYPE_REQ 0x0000   // request
#define MMTYPE_CNF 0x0001   // confirmation = +1
#define MMTYPE_IND 0x0002
#define MMTYPE_RSP 0x0003

/* Frametypes */

#define FRAME_IPV6 0x86DD
#define FRAME_HOMEPLUG 0x88E1


/* IPv6 functions */
void setSeccIp();
void IPv6Manager(uint16_t rxbytes); 
uint16_t calculateUdpAndTcpChecksumForIPv6(uint8_t *UdpOrTcpframe, uint16_t UdpOrTcpframeLen, const uint8_t *ipv6source, const uint8_t *ipv6dest, uint8_t nxt);


/* TCP functions */

void evaluateTcpPacket(void);
void tcp_prepareTcpHeader(uint8_t tcpFlag);
void tcp_packRequestIntoIp(void);

/* PLC functions */
void randomizeNmk();
void setNmkAt(uint16_t index);
void setNidAt(uint16_t index);
void setMacAt(uint8_t *mac, uint16_t offset);
void setRunId(uint16_t offset);
void setACVarField(uint16_t offset);
uint16_t getManagementMessageType();
uint16_t getFrameType();

// modem states
#define MODEM_POWERUP 0
#define MODEM_WRITESPACE 1
#define MODEM_CM_SET_KEY_REQ 2
#define MODEM_CM_SET_KEY_CNF 3
#define MODEM_CONFIGURED 10
#define SLAC_PARAM_CNF 20
#define MNBC_SOUND 30
#define ATTEN_CHAR_IND 40
#define ATTEN_CHAR_RSP 50
#define SLAC_MATCH_REQ 60

#define MODEM_GET_SW_REQ 100
#define MODEM_WAIT_SW 110
#define MODEM_LINK_READY 120


/* modem functios and exposed variables */
extern uint8_t modem_state;
extern uint8_t ModemsFound;
extern unsigned long SoundsTimer;
void ModemReset();
void composeSetKey();
void composeGetSwReq();
void composeSlacParamCnf();
void composeAttenCharInd();
void composeSlacMatchCnf();
void composeFactoryDefaults();

/* SLAC manager */
void SlacManager(uint16_t rxbytes);



/* other global vars */
extern uint8_t myModemMac[6]; 
extern uint8_t pevModemMac[6];

/* V2GTP */
#define V2GTP_HEADER_SIZE 8 /* header has 8 bytes */

extern uint8_t txbuffer[], rxbuffer[];
extern uint8_t myMac[];
extern uint8_t pevMac[];
extern uint8_t EVCCID[];
extern uint8_t EVSOC;