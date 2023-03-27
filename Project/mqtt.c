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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mqtt.h"
#include "timer.h"
#include "tcp.h"
#include "time.h"
#include "uart0.h"

// ------------------------------------------------------------------------------
//  Globals
// ------------------------------------------------------------------------------

    uint16_t subCount = 1;
// ------------------------------------------------------------------------------
//  Structures
// ------------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Subroutines
//-----------------------------------------------------------------------------
uint32_t calculateDataSize(const char* topic, const char* payload) {
    uint32_t dataSize = 0;
    uint32_t topicLength = strlen(topic);
    uint32_t payloadLength = strlen(payload);

    // Control Packet type and flags
    dataSize += 1;

    // Variable length field
    dataSize += encodeVariableLength(topicLength + payloadLength + 2, NULL);

    // Topic string
    dataSize += topicLength;

    // Payload string
    dataSize += payloadLength;

    return dataSize;
}
bool tcpIsMQTTCONNACK(etherHeader* ether, socket* s)
{
    bool ok = false;

    // Extract IP and TCP headers from the Ethernet header
    ipHeader* ip = (ipHeader*) ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    tcpHeader* tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);

    uint16_t dataSize = calculateTcpDataSize(tcp);

    // Calculate the length of the TCP segment (in bytes)
    uint16_t tcpSegmentLength = ntohs(ip->length) - ipHeaderLength;

    // Make sure there's enough data to examine
    if (tcpSegmentLength < 4) {
        return false;
    }

    // Check if the first four bytes match the expected format
    if (tcp->data[0] == 0x20) {
        ok = true;
    }


    return ok;
}
bool tcpIsMQTTSUBACK(etherHeader* ether, socket* s)
{
    bool ok = false;

    // Extract IP and TCP headers from the Ethernet header
    ipHeader* ip = (ipHeader*) ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    tcpHeader* tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);

    uint16_t dataSize = calculateTcpDataSize(tcp);

    // Calculate the length of the TCP segment (in bytes)
    uint16_t tcpSegmentLength = ntohs(ip->length) - ipHeaderLength;

    // Make sure there's enough data to examine
    if (tcpSegmentLength < 4) {
        return false;
    }

    // Check if the first byte matches the expected format for a SUBACK packet
    if (tcp->data[0] == 0x90) {
        ok = true;
    }

    return ok;
}
bool tcpIsMQTTUNSUBACK(etherHeader* ether, socket* s)
{
    bool ok = false;

    // Extract IP and TCP headers from the Ethernet header
    ipHeader* ip = (ipHeader*) ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    tcpHeader* tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);

    uint16_t dataSize = calculateTcpDataSize(tcp);

    // Calculate the length of the TCP segment (in bytes)
    uint16_t tcpSegmentLength = ntohs(ip->length) - ipHeaderLength;

    // Make sure there's enough data to examine
    if (tcpSegmentLength < 4) {
        return false;
    }

    // Check if the first byte matches the expected format for an UNSUBACK packet
    if ((tcp->data[0] & 0xF0) == 0xB0) {
        ok = true;

    }

    return ok;
}

uint8_t remainingLengthSize(uint16_t remainingLength)
{
    uint8_t size = 1;

    while (remainingLength > 127) {
        size++;
        remainingLength >>= 7;
    }

    return size;
}

uint16_t extractRemainingLength(uint8_t* buffer)
{
    uint16_t remainingLength = 0;
    uint8_t multiplier = 1;
    uint8_t encodedByte;

    do {
        encodedByte = *buffer++;
        remainingLength += (encodedByte & 127) * multiplier;
        multiplier *= 128;
    } while ((encodedByte & 128) != 0);

    return remainingLength;
}

void extractMQTTPayload(etherHeader* ether, socket* s) {
    // Extract IP and TCP headers from the Ethernet header
    ipHeader* ip = (ipHeader*) ether->data;
    tcpHeader* tcp = (tcpHeader*)((uint8_t*)ip + ((ip->size & 0x0F) * 4));

    uint16_t dataSize = tcp->data[1];
    uint16_t topicLength = tcp->data[2] | tcp->data[3];

    // Extract the topic and message from the MQTT payload
    char topic[30];
    char copy[30];

    int i;
    for(i = 0; i < topicLength;i++)

        copy[i] = (char)tcp->data[i+4];

    strncpy(topic, copy, topicLength);
    topic[topicLength] = '\0';


    uint8_t messageLength = dataSize - (topicLength + 2);

    char message[30];
    char messageCopy[30];

    int j = i + 4;
    for(i = 0;i < messageLength;i++)
        messageCopy[i] = (char)tcp->data[j++];

    strncpy(message, messageCopy, messageLength);
    message[messageLength] = '\0';

    // Display the topic and message in UART
    char uartMsg[100];
    sprintf(uartMsg, "Topic: %s\n", topic);
    putsUart0(uartMsg);
    sprintf(uartMsg, "Message: %s\n", message);
    putsUart0(uartMsg);
}

bool tcpIsMQTTPUBLISH(etherHeader* ether, socket* s) {
    bool ok = false;

    // Extract IP and TCP headers from the Ethernet header
    ipHeader* ip = (ipHeader*) ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    tcpHeader* tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);

    // Calculate the length of the TCP segment (in bytes)
    uint16_t tcpSegmentLength = ntohs(ip->length) - ipHeaderLength;

    // Calculate the length of the MQTT payload
    uint16_t mqttPayloadLength = tcpSegmentLength - tcp->offsetFields * 4 - 2; // Subtract 2 bytes for the packet ID

    // Make sure there's enough data to examine
    if (mqttPayloadLength < 1) {
        return false;
    }

    // Check if the first byte matches the expected format for a PUBLISH packet
    if ((tcp->data[0] & 0xF0) == 0x30) {
        // Extract the packet ID from the remaining bytes
        s->mqttPacketId = (tcp->data[2] << 8) | tcp->data[3];
        ok = true;
    }

    return ok;
}

void mqttSendPubAck(etherHeader* ether, socket s, uint16_t packetId) {

    uint8_t i;
    uint32_t sum;
    uint16_t tmp16;
    uint16_t tcpLength;
    uint8_t localHwAddress[6];
    uint8_t localIpAddress[4];

    // Ether frame

    getEtherMacAddress(localHwAddress);
    getIpAddress(localIpAddress);
    for (i = 0; i < HW_ADD_LENGTH; i++)
    {
        ether->destAddress[i] = s.remoteHwAddress[i];
        ether->sourceAddress[i] = localHwAddress[i];
    }
    ether->frameType = htons(TYPE_IP);

    // IP header
    ipHeader* ip = (ipHeader*)ether->data;
    ip->rev = 0x4;
    ip->size = 0x5;
    uint8_t ipHeaderLength = ip->size * 4;
    ip->typeOfService = 0;
    ip->id = 0;
    ip->flagsAndOffset = 0;
    ip->ttl = 128;
    ip->protocol = PROTOCOL_TCP; // set protocol to MQTT
    ip->headerChecksum = 0;
     for (i = 0; i < IP_ADD_LENGTH; i++)
    {
        ip->destIp[i] = s.remoteIpAddress[i];
        ip->sourceIp[i] = localIpAddress[i];
    }

    // TCP header
    tcpHeader* tcp = (tcpHeader*)((uint8_t*)ip + (ip->size * 4));

    tcp->sourcePort = htons(s.localPort);
    tcp->destPort = htons(s.remotePort);

    //initial sequence number
    tcp->sequenceNumber = htonl(s.sequenceNumber);
    tcp->acknowledgementNumber = htonl(s.acknowledgementNumber);

    tcp->offsetFields = htons(0x5010); // set data offset and ACK flag

    // add PUBACK message to tcp data
    uint8_t puback[4] = {0x40, 0x02, 0x00, 0x02}; // PUBACK message bytes
    uint16_t* packetIdPtr = (uint16_t*)(puback + 2);
    *packetIdPtr = htons(packetId);

    // adjust lengths
    tcpLength = sizeof(tcpHeader) + sizeof(puback);
    ip->length = htons(ipHeaderLength + tcpLength);

    // 32-bit sum over ip header
    calcIpChecksum(ip);

    // set tcp length
    tcpLength = htons(tcpLength);

    // add tcp header
    tcp->checksum = 0;
    sum = 0;
    sumIpWords(&ip->sourceIp, 8, &sum);

    tmp16 = ip->protocol;
    sum += (tmp16 & 0xff) << 8;
    sumIpWords(&tcpLength, 2, &sum);
    sumIpWords(tcp, tcpLength, &sum);

    tcp->checksum = getIpChecksum(sum);

    // send packet with size = ether + tcp hdr + ip header + puback_size
    putEtherPacket(ether, sizeof(etherHeader) + ipHeaderLength + tcpLength);
}


void sendMqttConnectAck(etherHeader *ether, socket s, uint8_t data[], uint16_t dataSize)
{
    uint8_t i;
    uint32_t sum;
    uint16_t tmp16;
    uint16_t tcpLength;
    uint8_t *copyData;
    uint8_t localHwAddress[6];
    uint8_t localIpAddress[4];

    // Ether frame

    getEtherMacAddress(localHwAddress);
    getIpAddress(localIpAddress);
    for (i = 0; i < HW_ADD_LENGTH; i++)
    {
        ether->destAddress[i] = s.remoteHwAddress[i];
        ether->sourceAddress[i] = localHwAddress[i];
    }
    ether->frameType = htons(TYPE_IP);

    // IP header
    ipHeader* ip = (ipHeader*)ether->data;
    ip->rev = 0x4;
    ip->size = 0x5;
    uint8_t ipHeaderLength = ip->size * 4;
    ip->typeOfService = 0;
    ip->id = 0;
    ip->flagsAndOffset = 0;
    ip->ttl = 128;
    ip->protocol = PROTOCOL_TCP;
    ip->headerChecksum = 0;
     for (i = 0; i < IP_ADD_LENGTH; i++)
    {
        ip->destIp[i] = s.remoteIpAddress[i];
        ip->sourceIp[i] = localIpAddress[i];
    }

    // TCP header
    tcpHeader* tcp = (tcpHeader*)((uint8_t*)ip + (ip->size * 4));


    tcp->sourcePort = htons(s.localPort);
    tcp->destPort = htons(s.remotePort);

    //initial sequence number
    tcp->sequenceNumber = htonl(s.sequenceNumber) ;
    tcp->acknowledgementNumber = htonl(s.acknowledgementNumber);

   //tcp->offsetFields = htons(0x0010| (sizeof(tcpHeader)/4) << 12);
    tcp->offsetFields = htons(0x5010);


    // adjust lengths
    tcpLength = sizeof(tcpHeader) + dataSize;
    ip->length = htons(ipHeaderLength + tcpLength);

    // 32-bit sum over ip header
    calcIpChecksum(ip);

    // set tcp length
    tcpLength = htons(tcpLength);

    copyData = tcp->data;
    for (i = 0; i < dataSize; i++)
        copyData[i] = data[i];

    // 32-bit sum over pseudo-header
    sum = 0;
    sumIpWords(ip->sourceIp, 8, &sum);
    tmp16 = ip->protocol;
    sum += (tmp16 & 0xff) << 8;

    sumIpWords(&tcpLength, 2, &sum);
    tcpLength = htons(tcpLength);

    // add tcp header
    tcp->checksum = 0;
    sumIpWords(tcp, tcpLength, &sum);

    tcp->checksum = getIpChecksum(sum);

    // send packet with size = ether + tcp hdr + ip header + udp_size
    putEtherPacket(ether, sizeof(etherHeader) + ipHeaderLength + tcpLength);

}
#define MAX_REMAINING_LENGTH_SIZE 4

uint8_t encodeVariableLength(uint32_t length, uint8_t* output)
{
    uint8_t digitCount = 0;
    do {
        output[digitCount] = length % 128;
        length /= 128;
        if (length > 0) {
            output[digitCount] |= 128;
        }
        digitCount++;
    } while (length > 0 && digitCount < MAX_REMAINING_LENGTH_SIZE);

    return digitCount;
}
// Encode remaining length field in MQTT packet
uint8_t encodeRemainingLength(uint16_t length, uint8_t* tcpData)
{
    uint8_t encodedByte = 0;

    do {
        uint8_t encoded = length % 128;
        length /= 128;
        if (length > 0) {
            encoded |= 0x80;
        }
        encodedByte++;
        tcpData[encodedByte + 1] = encoded;
    } while (length > 0 && encodedByte < 4);

    return encodedByte;
}
// Send MQTT connect message
void mqttConnectMessage(etherHeader *ether, socket s, uint32_t flags, uint8_t dataM[], uint16_t dataSize)
{
    uint8_t i;
    uint32_t sum;
    uint16_t tmp16;
    uint16_t tcpLength;
    uint8_t localHwAddress[6];
    uint8_t localIpAddress[4];

    // Ether frame
    getEtherMacAddress(localHwAddress);
    getIpAddress(localIpAddress);
    for (i = 0; i < HW_ADD_LENGTH; i++)
    {
        ether->destAddress[i] = s.remoteHwAddress[i];
        ether->sourceAddress[i] = localHwAddress[i];
    }
    ether->frameType = htons(TYPE_IP);

    // IP header
    ipHeader* ip = (ipHeader*)ether->data;
    ip->rev = 0x4;
    ip->size = 0x5;
    uint8_t ipHeaderLength = ip->size * 4;
    ip->typeOfService = 0;
    ip->id = 0;
    ip->flagsAndOffset = 0;
    ip->ttl = 128;
    ip->protocol = PROTOCOL_TCP;
    ip->headerChecksum = 0;
     for (i = 0; i < IP_ADD_LENGTH; i++)
    {
        ip->destIp[i] = s.remoteIpAddress[i];
        ip->sourceIp[i] = localIpAddress[i];
    }

    // TCP header
    tcpHeader* tcp = (tcpHeader*)((uint8_t*)ip + (ip->size * 4));

    tcp->sourcePort = htons(s.localPort);
    tcp->destPort = htons(s.remotePort);


    int dataLength = 0;

    //Connect Packet
    tcp->data[dataLength++] = 0x10;
    tcp->data[dataLength++] = 0x00;

    // Protocol Name
    tcp->data[dataLength++] = 0x00;
    tcp->data[dataLength++] = 0x04;
    tcp->data[dataLength++] = 'M';
    tcp->data[dataLength++] = 'Q';
    tcp->data[dataLength++] = 'T';
    tcp->data[dataLength++] = 'T';

    // Protocol Level
    tcp->data[dataLength++] = 0x04;

    // Connect Flags
    tcp->data[dataLength++] = 0x00;

    // Keep Alive
    tcp->data[dataLength++] = 0xFF;
    tcp->data[dataLength++] = 0xFF;

    // Client ID
    tcp->data[dataLength++] = 0x00;
    tcp->data[dataLength++] = 0x04;
    tcp->data[dataLength++] = 't';
    tcp->data[dataLength++] = 'e';
    tcp->data[dataLength++] = 's';
    tcp->data[dataLength++] = 't';


    tcp->data[1] = dataLength - 2;


    //initial sequence number
    tcp->sequenceNumber = htonl(s.sequenceNumber);
    tcp->acknowledgementNumber = htonl(s.acknowledgementNumber);


    tcp->offsetFields = htons(flags| (sizeof(tcpHeader)/4) << 12);
    tcp->windowSize = htons(1500);


    // adjust lengths
    tcpLength = sizeof(tcpHeader) + dataLength;
    ip->length = htons(ipHeaderLength + tcpLength);

    // 32-bit sum over ip header
    calcIpChecksum(ip);

    // set tcp length
    tcpLength = htons(tcpLength);



    // 32-bit sum over pseudo-header
    sum = 0;
    sumIpWords(ip->sourceIp, 8, &sum);
    tmp16 = ip->protocol;
    sum += (tmp16 & 0xff) << 8;

    sumIpWords(&tcpLength, 2, &sum);
    tcpLength = htons(tcpLength);

    // add tcp header
    tcp->checksum = 0;
    sumIpWords(tcp, tcpLength, &sum);

    tcp->checksum = getIpChecksum(sum);

    // send packet with size = ether + tcp hdr + ip header + udp_size
    putEtherPacket(ether, sizeof(etherHeader) + ipHeaderLength + tcpLength);
}
void mqttDisConnectMessage(etherHeader *ether, socket s, uint32_t flags, uint8_t dataM[], uint16_t dataSize)
{
    uint8_t i;
    uint32_t sum;
    uint16_t tmp16;
    uint16_t tcpLength;
    uint8_t localHwAddress[6];
    uint8_t localIpAddress[4];

    // Ether frame
    getEtherMacAddress(localHwAddress);
    getIpAddress(localIpAddress);
    for (i = 0; i < HW_ADD_LENGTH; i++)
    {
        ether->destAddress[i] = s.remoteHwAddress[i];
        ether->sourceAddress[i] = localHwAddress[i];
    }
    ether->frameType = htons(TYPE_IP);

    // IP header
    ipHeader* ip = (ipHeader*)ether->data;
    ip->rev = 0x4;
    ip->size = 0x5;
    uint8_t ipHeaderLength = ip->size * 4;
    ip->typeOfService = 0;
    ip->id = 0;
    ip->flagsAndOffset = 0;
    ip->ttl = 128;
    ip->protocol = PROTOCOL_TCP;
    ip->headerChecksum = 0;
     for (i = 0; i < IP_ADD_LENGTH; i++)
    {
        ip->destIp[i] = s.remoteIpAddress[i];
        ip->sourceIp[i] = localIpAddress[i];
    }

    // TCP header
    tcpHeader* tcp = (tcpHeader*)((uint8_t*)ip + (ip->size * 4));

    tcp->sourcePort = htons(s.localPort);
    tcp->destPort = htons(s.remotePort);

    //initial sequence number
    tcp->sequenceNumber = htonl(s.sequenceNumber);
    tcp->acknowledgementNumber = htonl(s.acknowledgementNumber);


    tcp->offsetFields = htons(flags| (sizeof(tcpHeader)/4) << 12);
    tcp->windowSize = htons(1500);

    int dataLength = 0;

    //Disconnect Packet
    tcp->data[dataLength++] = 0xE0;
    tcp->data[dataLength++] = 0x00;


    // adjust lengths
    tcpLength = sizeof(tcpHeader) + dataLength;
    ip->length = htons(ipHeaderLength + tcpLength);

    // 32-bit sum over ip header
    calcIpChecksum(ip);

    // set tcp length
    tcpLength = htons(tcpLength);

    // 32-bit sum over pseudo-header
    sum = 0;
    sumIpWords(ip->sourceIp, 8, &sum);
    tmp16 = ip->protocol;
    sum += (tmp16 & 0xff) << 8;

    sumIpWords(&tcpLength, 2, &sum);
    tcpLength = htons(tcpLength);

    // add tcp header
    tcp->checksum = 0;
    sumIpWords(tcp, tcpLength, &sum);

    tcp->checksum = getIpChecksum(sum);

    // send packet with size = ether + tcp hdr + ip header + udp_size
    putEtherPacket(ether, sizeof(etherHeader) + ipHeaderLength + tcpLength);
}
uint8_t* writeString(uint8_t* buffer, const char* str) {
    uint16_t length = strlen(str);
    *buffer++ = length >> 8;
    *buffer++ = length & 0xFF;
    memcpy(buffer, str, length);
    return buffer + length;
}
void mqttPublishMessage(etherHeader* ether, socket s, const char* topic, const char* payload)
{
    uint8_t i;
    uint32_t sum;
    uint16_t tmp16;
    uint16_t tcpLength;
    uint8_t localHwAddress[6];
    uint8_t localIpAddress[4];

    // Ether frame
    getEtherMacAddress(localHwAddress);
    getIpAddress(localIpAddress);
    for (i = 0; i < HW_ADD_LENGTH; i++)
    {
        ether->destAddress[i] = s.remoteHwAddress[i];
        ether->sourceAddress[i] = localHwAddress[i];
    }
    ether->frameType = htons(TYPE_IP);

    // IP header
    ipHeader* ip = (ipHeader*)ether->data;
    ip->rev = 0x4;
    ip->size = 0x5;
    uint8_t ipHeaderLength = ip->size * 4;
    ip->typeOfService = 0;
    ip->id = 0;
    ip->flagsAndOffset = 0;
    ip->ttl = 128;
    ip->protocol = PROTOCOL_TCP;
    ip->headerChecksum = 0;
     for (i = 0; i < IP_ADD_LENGTH; i++)
    {
        ip->destIp[i] = s.remoteIpAddress[i];
        ip->sourceIp[i] = localIpAddress[i];
    }

    // TCP header
    tcpHeader* tcp = (tcpHeader*)((uint8_t*)ip + (ip->size * 4));

    tcp->sourcePort = htons(s.localPort);
    tcp->destPort = htons(s.remotePort);

    //initial sequence number
    tcp->sequenceNumber = htonl(s.sequenceNumber);
    tcp->acknowledgementNumber = htonl(s.acknowledgementNumber);

    int dataLength = 0;

    //MQTT Publish Packet
    tcp->data[dataLength++] = 0x30;
    tcp->data[dataLength++] = 0x00;


    // Encode Topic
    uint32_t topicLength = strlen(topic);
    tcp->data[dataLength++] = topicLength >> 8;  // MSB of Topic Length
    tcp->data[dataLength++] = topicLength & 0xFF;  // LSB of Topic Length
    for (i = 0; i < topicLength; i++)
    {
        tcp->data[dataLength++] = topic[i];
    }

    // Encode Payload
    uint32_t payloadLength = strlen(payload);
    for (i = 0; i < payloadLength; i++)
    {
        tcp->data[dataLength++] = payload[i];
    }

    // Calculate Remaining Length
    uint32_t remainingLength = payloadLength + topicLength + 2;  // Add 2 for 2 bytes of Topic Length
    uint8_t encodedRemainingLength[5];
    uint8_t encodedRemainingLengthSize = encodeRemainingLength(remainingLength, encodedRemainingLength);

    // Encode Remaining Length
    for (i = 0; i < encodedRemainingLengthSize; i++)
    {
        tcp->data[dataLength++] = encodedRemainingLength[i];
    }

    //initial sequence number

    tcp->offsetFields = htons(0x0018| (sizeof(tcpHeader)/4) << 12);
    tcp->windowSize = htons(1500);

    // adjust lengths
    tcpLength = sizeof(tcpHeader) + dataLength;
    ip->length = htons(ipHeaderLength + tcpLength);
    tcp->data[1] = dataLength - 2;

    // 32-bit sum over ip header
    calcIpChecksum(ip);

    // set tcp length
    tcpLength = htons(tcpLength);

    // 32-bit sum over pseudo-header
    sum = 0;
    sumIpWords(ip->sourceIp, 8, &sum);
    tmp16 = ip->protocol;
    sum += (tmp16 & 0xff) << 8;

    sumIpWords(&tcpLength, 2, &sum);
    tcpLength = htons(tcpLength);

    // add tcp header
    tcp->checksum = 0;
    sumIpWords(tcp, tcpLength, &sum);

    tcp->checksum = getIpChecksum(sum);

    // send packet with size = ether + tcp hdr + ip header + mqtt size
    putEtherPacket(ether, sizeof(etherHeader) + ipHeaderLength + tcpLength);
}
void mqttUnsubscribeMessage(etherHeader* ether, socket s, char* topic)
{
    uint8_t i;
    uint32_t sum;
    uint16_t tmp16;
    uint16_t tcpLength;
    uint8_t localHwAddress[6];
    uint8_t localIpAddress[4];

    // Ether frame
    getEtherMacAddress(localHwAddress);
    getIpAddress(localIpAddress);
    for (i = 0; i < HW_ADD_LENGTH; i++)
    {
        ether->destAddress[i] = s.remoteHwAddress[i];
        ether->sourceAddress[i] = localHwAddress[i];
    }
    ether->frameType = htons(TYPE_IP);

    // IP header
    ipHeader* ip = (ipHeader*)ether->data;
    ip->rev = 0x4;
    ip->size = 0x5;
    uint8_t ipHeaderLength = ip->size * 4;
    ip->typeOfService = 0;
    ip->id = 0;
    ip->flagsAndOffset = 0;
    ip->ttl = 128;
    ip->protocol = PROTOCOL_TCP;
    ip->headerChecksum = 0;
     for (i = 0; i < IP_ADD_LENGTH; i++)
    {
        ip->destIp[i] = s.remoteIpAddress[i];
        ip->sourceIp[i] = localIpAddress[i];
    }

    // TCP header
    tcpHeader* tcp = (tcpHeader*)((uint8_t*)ip + (ip->size * 4));

    tcp->sourcePort = htons(s.localPort);
    tcp->destPort = htons(s.remotePort);

    //initial sequence number
    tcp->sequenceNumber = htonl(s.sequenceNumber);
    tcp->acknowledgementNumber = htonl(s.acknowledgementNumber);

    int dataLength = 0;

    //MQTT Unsubscribe Packet
    tcp->data[dataLength++] = 0xA2;
    tcp->data[dataLength++] = 0x00;

    // Encode Packet Identifier
    uint16_t packetIdentifier = subCount++; // change this to a unique value
    tcp->data[dataLength++] = packetIdentifier >> 8;  // MSB of Packet Identifier
    tcp->data[dataLength++] = packetIdentifier & 0xFF;  // LSB of Packet Identifier

    // Encode Topic Filter
    uint32_t topicLength = strlen(topic);
    tcp->data[dataLength++] = topicLength >> 8;  // MSB of Topic Length
    tcp->data[dataLength++] = topicLength & 0xFF;  // LSB of Topic Length
    for (i = 0; i < topicLength; i++)
    {
        tcp->data[dataLength++] = topic[i];
    }
    tcp->data[1] = dataLength - 2;
    // Calculate the total length of the MQTT unsubscribe message, which consists of:
    //   - A fixed header (2 bytes)
    //   - A variable header (2 bytes message identifier)
    //   - A payload (one or more topic filters to unsubscribe from)
    //
    // Calculate Remaining Length
    uint32_t remainingLength = topicLength + 5;
    uint8_t encodedRemainingLength[5];
    uint8_t encodedRemainingLengthSize = encodeRemainingLength(remainingLength, encodedRemainingLength);

    // Encode Remaining Length
    for (i = 0; i < encodedRemainingLengthSize; i++)
    {
        tcp->data[dataLength++] = encodedRemainingLength[i];
    }

    tcp->offsetFields = htons(0x0018 | (sizeof(tcpHeader) / 4) << 12);
    tcp->windowSize = htons(1500);

    // adjust lengths
    tcpLength = sizeof(tcpHeader) + dataLength;
    ip->length = htons(ipHeaderLength + tcpLength);

    // calculate IP header checksum
    calcIpChecksum(ip);

    // set tcp length
    tcpLength = htons(tcpLength);

    // calculate checksum over pseudo-header and tcp segment
    sum = 0;
    sumIpWords(ip->sourceIp, 8, &sum);
    tmp16 = ip->protocol;
    sum += (tmp16 & 0xff) << 8;
    sumIpWords(&tcpLength, 2, &sum);
    sumIpWords(tcp, tcpLength, &sum);

    // set tcp checksum
    tcp->checksum = getIpChecksum(sum);

    // send packet with size = ether + tcp hdr + ip header + mqtt size
    putEtherPacket(ether, sizeof(etherHeader) + ipHeaderLength + tcpLength);
    putsUart0("Made it here - end message \n");

}
void mqttSubscribeMessage(etherHeader* ether, socket s, const char* topic)
{
    uint8_t i;
    uint32_t sum;
    uint16_t tmp16;
    uint16_t tcpLength;
    uint8_t localHwAddress[6];
    uint8_t localIpAddress[4];

    // Ether frame
    getEtherMacAddress(localHwAddress);
    getIpAddress(localIpAddress);
    for (i = 0; i < HW_ADD_LENGTH; i++)
    {
        ether->destAddress[i] = s.remoteHwAddress[i];
        ether->sourceAddress[i] = localHwAddress[i];
    }
    ether->frameType = htons(TYPE_IP);

    // IP header
    ipHeader* ip = (ipHeader*)ether->data;
    ip->rev = 0x4;
    ip->size = 0x5;
    uint8_t ipHeaderLength = ip->size * 4;
    ip->typeOfService = 0;
    ip->id = 0;
    ip->flagsAndOffset = 0;
    ip->ttl = 128;
    ip->protocol = PROTOCOL_TCP;
    ip->headerChecksum = 0;
     for (i = 0; i < IP_ADD_LENGTH; i++)
    {
        ip->destIp[i] = s.remoteIpAddress[i];
        ip->sourceIp[i] = localIpAddress[i];
    }

    // TCP header
    tcpHeader* tcp = (tcpHeader*)((uint8_t*)ip + (ip->size * 4));

    tcp->sourcePort = htons(s.localPort);
    tcp->destPort = htons(s.remotePort);

    //initial sequence number
    tcp->sequenceNumber = htonl(s.sequenceNumber);
    tcp->acknowledgementNumber = htonl(s.acknowledgementNumber);

    int dataLength = 0;

    //MQTT Subscribe Packet
    tcp->data[dataLength++] = 0x82;
    tcp->data[dataLength++] = 0x00;

    // Encode Packet Identifier
    uint16_t packetIdentifier = subCount++;; // change this to a unique value
    tcp->data[dataLength++] = packetIdentifier >> 8;  // MSB of Packet Identifier
    tcp->data[dataLength++] = packetIdentifier & 0xFF;  // LSB of Packet Identifier

    // Encode Topic Filter
    uint32_t topicLength = strlen(topic);
    tcp->data[dataLength++] = topicLength >> 8;  // MSB of Topic Length
    tcp->data[dataLength++] = topicLength & 0xFF;  // LSB of Topic Length
    for (i = 0; i < topicLength; i++)
    {
        tcp->data[dataLength++] = topic[i];
    }

    // Calculate Remaining Length
    uint32_t remainingLength = topicLength + 5;
    uint8_t encodedRemainingLength[5];
    uint8_t encodedRemainingLengthSize = encodeRemainingLength(remainingLength, encodedRemainingLength);

    // Encode Remaining Length
    for (i = 0; i < encodedRemainingLengthSize; i++)
    {
        tcp->data[dataLength++] = encodedRemainingLength[i];
    }
    tcp->data[1] = dataLength - 2;
    //initial sequence number

    tcp->offsetFields = htons(0x0018 | (sizeof(tcpHeader) / 4) << 12);
    tcp->windowSize = htons(1500);

    // adjust lengths
    tcpLength = sizeof(tcpHeader) + dataLength;
    ip->length = htons(ipHeaderLength + tcpLength);


    // 32-bit sum over ip header
    calcIpChecksum(ip);

    // set tcp length
    tcpLength = htons(tcpLength);

    // 32-bit sum over pseudo-header
    sum = 0;
    sumIpWords(ip->sourceIp, 8, &sum);
    tmp16 = ip->protocol;
    sum += (tmp16 & 0xff) << 8;

    sumIpWords(&tcpLength, 2, &sum);
    tcpLength = htons(tcpLength);

    // add tcp header
    tcp->checksum = 0;
    sumIpWords(tcp, tcpLength, &sum);

    tcp->checksum = getIpChecksum(sum);

    // send packet with size = ether + tcp hdr + ip header + mqtt size
    putEtherPacket(ether, sizeof(etherHeader) + ipHeaderLength + tcpLength);
}
