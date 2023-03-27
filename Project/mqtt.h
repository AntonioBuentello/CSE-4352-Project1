// MQTT Library (framework only)
// Jason Losh

//-----------------------------------------------------------------------------
// Hardware Target
//-----------------------------------------------------------------------------

// Target Platform: -
// Target uC:       -
// System Clock:    -

// Hardware configuration:
// -

//-----------------------------------------------------------------------------
// Device includes, defines, and assembler directives
//-----------------------------------------------------------------------------

#ifndef MQTT_H_
#define MQTT_H_

#include <stdint.h>
#include <stdbool.h>
#include "tcp.h"

//-----------------------------------------------------------------------------
// Subroutines
//-----------------------------------------------------------------------------
typedef struct {
    uint8_t type;
    uint8_t flags;
    uint16_t length;
    uint8_t* data;
} mqttHeader;
typedef struct {
    uint8_t type;
    uint8_t code;
} mqttConnectAckHeader;

void extractMQTTPayload(etherHeader* ether, socket* s);

mqttHeader* decodeMQTT(uint8_t* buffer, size_t length);
bool tcpIsMQTTCONNACK(etherHeader* ether, socket* s);
bool tcpIsMQTTSUBACK(etherHeader* ether, socket* s);
bool tcpIsMQTTUNSUBACK(etherHeader* ether, socket* s);
bool tcpIsMQTTPUBLISH(etherHeader* ether, socket* s);


uint8_t encodeRemainingLength(uint16_t length, uint8_t* tcpData);
uint8_t encodeVariableLength(uint32_t length, uint8_t* output);

void mqttConnectMessage(etherHeader *ether, socket s, uint32_t flags, uint8_t data[], uint16_t dataSize);
void mqttDisConnectMessage(etherHeader *ether, socket s, uint32_t flags, uint8_t dataM[], uint16_t dataSize);
void sendMqttConnectAck(etherHeader *ether, socket s, uint8_t data[], uint16_t dataSize);

uint32_t calculateDataSize(const char* topic, const char* payload);
void mqttPublishMessage(etherHeader* ether, socket s, const char* topic, const char* payload);
void mqttSubscribeMessage(etherHeader* ether, socket s, const char
                          * topic);
void mqttUnsubscribeMessage(etherHeader* ether, socket s, char* topic);

uint8_t remainingLengthSize(uint16_t remainingLength);
uint16_t extractRemainingLength(uint8_t* buffer);


void mqttSendPubAck(etherHeader* ether, socket s, uint16_t packetId);






#endif

