// TCP Library (framework only)
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
#include <string.h>
#include "tcp.h"
#include "timer.h"
#include "math.h"
#include "arp.h"
#include "uart0.h"

// ------------------------------------------------------------------------------
//  Globals
// ------------------------------------------------------------------------------

uint32_t isn = 0;
uint16_t mss = 1500;

uint16_t dSize;


// ------------------------------------------------------------------------------
//  Structures
// ------------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Subroutines
//-----------------------------------------------------------------------------

// Determines whether packet is TCP packet
// Must be an IP packet

uint16_t calculateTcpDataSize(tcpHeader *tcp) {
    // The data offset field specifies the length of the TCP header in 32-bit words
    uint8_t dataOffset = (tcp->offsetFields >> 12) * 4;

    // The total packet size can be determined from the IP length field
    ipHeader *ip = (ipHeader*)((uint8_t*)tcp - sizeof(ipHeader));
    uint16_t packetSize = ntohs(ip->length);

    // Calculate the size of the data by subtracting the TCP header length from the total packet length
    uint16_t dataSize = packetSize - (sizeof(ipHeader) + dataOffset);
    return dataSize;
}
bool tcpIsAckSyn(etherHeader *ether, socket *s){

    bool ok = false;

    uint16_t flagvalue = 0;

    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);

    if(tcp->offsetFields == 4704){

        flagvalue = tcp->offsetFields >> 8;

        if(flagvalue && 0x10 | 0x02){

            ok = true;
        }
    }
    return ok;
}
bool tcpIsAck(etherHeader *ether, socket *s)
{
    bool ok = false;

    uint16_t flagvalue = 0;

    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);

    if(tcp->offsetFields == 4176){

        flagvalue = tcp->offsetFields >> 8;

        if(flagvalue && 0x10){

            ok = true;
        }

    }
    if(tcp->offsetFields == 6224){

        flagvalue = tcp->offsetFields >> 8;

        if(flagvalue && 0x18){

            ok = true;
        }

    }


    return ok;
}
bool tcpIsFinAck(etherHeader *ether, socket *s){
    bool ok = false;

    uint16_t flagvalue = 0;

    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);

    if (tcp->offsetFields == 4432) {

        flagvalue = tcp->offsetFields >> 8;

        if (flagvalue && 0x11 ) {
            ok = true;
        }
    }

    return ok;
}
//bool tcpIsFinAck(etherHeader *ether, socket *s){

bool isTcp(etherHeader* ether)
{
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    tcpHeader* tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);
    bool ok;
    uint16_t tmp16;
    uint32_t sum = 0;
    ok = (ip->protocol == PROTOCOL_TCP);
    if (ok)
    {
        // 32-bit sum over pseudo-header
        sumIpWords(ip->sourceIp, 8, &sum);
        tmp16 = ip->protocol;
        sum += (tmp16 & 0xff) << 8;
        tmp16 = htons(ntohs(ip->length) - (ip->size * 4));
        sumIpWords(&tmp16, 2, &sum);
        // add tcp header and data
        sumIpWords(tcp, ntohs(ip->length) - (ip->size * 4), &sum);
        ok = (getIpChecksum(sum) == 0);
    }
    return ok;
}

uint8_t* getTcpData(etherHeader *ether, socket *s)
{

    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ipHeaderLength);

    uint16_t dataSize;

    if(s->state != ESTABLISHED)
        dataSize = 1;
    else
    {
        uint16_t tcpLength = ((tcp->offsetFields & 0xF0) >> 4) * 4;
        uint16_t ipLength = ip->size * 4;
        uint16_t totalSize = ntohs(ip->length);
        dataSize = totalSize - ipLength - tcpLength;
    }

    s->sequenceNumber = htonl(tcp->acknowledgementNumber);
    s->acknowledgementNumber = htonl(tcp->sequenceNumber) + dataSize;

    return tcp->data;
}
// Get socket information from a received TCP message
void getTcpMessageSocket(etherHeader *ether, socket *s)
{
    ipHeader *ip = (ipHeader*)ether->data;
    uint8_t ipHeaderLength = ip->size * 4;
    arpPacket *arp = (arpPacket*)((uint8_t*)ip + ipHeaderLength);

    uint8_t i;
    for (i = 0; i < HW_ADD_LENGTH; i++)
        s->remoteHwAddress[i] = arp->sourceAddress[i];
    for (i = 0; i < IP_ADD_LENGTH; i++)
        s->remoteIpAddress[i] = arp->sourceIp[i];

    //try this
    s->remotePort = 1883;
    s->localPort = (random32() % 16383) + 49152;

}

// Send TCP message
void sendTcpMessage(etherHeader *ether, socket s, uint32_t flags, uint8_t data[], uint16_t dataSize)
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

    tcp->sequenceNumber = htonl(s.sequenceNumber);
    tcp->acknowledgementNumber = htonl(s.acknowledgementNumber);

    // adjust lengths
    tcpLength = sizeof(tcpHeader) + dataSize;
    ip->length = htons(ipHeaderLength + tcpLength);


    tcp->offsetFields = htons(flags| (sizeof(tcpHeader)/4) << 12);
    tcp->windowSize = htons(1500);

    // 32-bit sum over ip header
    calcIpChecksum(ip);

    // set tcp length
    tcpLength = htons(tcpLength);

    // copy data
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
