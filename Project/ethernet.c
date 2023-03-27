// Ethernet Example
// Jason Losh

//-----------------------------------------------------------------------------
// Hardware Target
//-----------------------------------------------------------------------------

// Target Platform: EK-TM4C123GXL w/ ENC28J60
// Target uC:       TM4C123GH6PM
// System Clock:    40 MHz

// Hardware configuration:
// ENC28J60 Ethernet controller on SPI0
//   MOSI (SSI0Tx) on PA5
//   MISO (SSI0Rx) on PA4
//   SCLK (SSI0Clk) on PA2
//   ~CS (SW controlled) on PA3
//   WOL on PB3
//   INT on PC6

// Pinning for IoT projects with wireless modules:
// N24L01+ RF transceiver
//   MOSI (SSI0Tx) on PA5
//   MISO (SSI0Rx) on PA4
//   SCLK (SSI0Clk) on PA2
//   ~CS on PE0
//   INT on PB2
// Xbee module
//   DIN (UART1TX) on PC5
//   DOUT (UART1RX) on PC4

//-----------------------------------------------------------------------------
// Device includes, defines, and assembler directives
//-----------------------------------------------------------------------------

#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "tm4c123gh6pm.h"
#include "clock.h"
#include "eeprom.h"
#include "gpio.h"
#include "spi0.h"
#include "uart0.h"
#include "wait.h"
#include "timer.h"
#include "eth0.h"
#include "arp.h"
#include "ip.h"
#include "icmp.h"
#include "udp.h"
#include "tcp.h"
#include "mqtt.h"
#include "firewall.h"

// Pins
#define RED_LED PORTF,1
#define BLUE_LED PORTF,2
#define GREEN_LED PORTF,3
#define PUSH_BUTTON PORTF,4

// EEPROM Map
#define EEPROM_DHCP        1
#define EEPROM_IP          2
#define EEPROM_SUBNET_MASK 3
#define EEPROM_GATEWAY     4
#define EEPROM_DNS         5
#define EEPROM_TIME        6
#define EEPROM_MQTT        7
#define EEPROM_ERASED      0xFFFFFFFF

//flags
uint8_t sendArpFlag = 0;
uint8_t sendSynFlag = 0;
uint8_t sendAckFlag = 0;
uint8_t sendMqttConnFlag = 0;
uint8_t sendMqttDisConnFlag = 0;
uint8_t sendMqttAckFlag = 0;

uint8_t mqttConnFlag = 0;

uint8_t mqttPubFlag = 0;
uint8_t mqttSubFlag = 0;
uint8_t mqttUnsubFlag = 0;
uint8_t disFinAckResp = 0;


char *pubTopic;
char *pubData;

char *subTopic;
char *unsubTopic;

typedef enum mqttSTATES{
    DISCONNECTED = 0,
    CONNECTING,
    CONNECTED,
    DISCONNECTING,
}mqttSTATES;

#define MAX_PACKET_SIZE 1522
uint8_t remote_ip[4];
uint8_t local_ip[4];

uint8_t datas[];
uint32_t payloadSize;

uint8_t buffer[MAX_PACKET_SIZE];
etherHeader *data = (etherHeader*) buffer;
socket s;
mqttHeader* header = NULL;


mqttSTATES mqttStates = DISCONNECTED;

whitelist_entry whitelist[NUM_WHITELIST_ENTRIES] = {
    {{192, 168, 1, 1}, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
    {{192, 168, 1, 102}, {2, 3, 4, 5, 6, 102}}
};


//-----------------------------------------------------------------------------
// Subroutines                
//-----------------------------------------------------------------------------

// Initialize Hardware
void initHw()
{
    // Initialize system clock to 40 MHz
    initSystemClockTo40Mhz();

    // Enable clocks
    enablePort(PORTF);
    _delay_cycles(3);

    // Configure LED and pushbutton pins
    selectPinPushPullOutput(RED_LED);
    selectPinPushPullOutput(GREEN_LED);
    selectPinPushPullOutput(BLUE_LED);
    selectPinDigitalInput(PUSH_BUTTON);
    enablePinPullup(PUSH_BUTTON);
}

// Define an array of strings that maps the numerical values to their corresponding names
char* state_names[] = {"CLOSED", "LISTEN", "SYN_SENT", "SYN_RECEIVED", "ESTABLISHED", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "TIMEWAIT", "LAST_ACK"};
char* mqtt_state_names[] = {"DISCONNECTED", "CONNECTING", "CONNECTED", "DISCONNECTING"};

void displayStatusInfo()
{
    uint8_t i;
    char str[10];
    uint8_t ip[4];

    putcUart0('\n');
    getIpAddress(ip);
    putsUart0("  IP:    ");
    for (i = 0; i < IP_ADD_LENGTH; i++)
    {
        snprintf(str, sizeof(str), "%"PRIu8, ip[i]);
        putsUart0(str);
        if (i < IP_ADD_LENGTH-1)
            putcUart0('.');
    }
    putcUart0('\n');
    getIpMqttBrokerAddress(ip);
    putsUart0("  MQTT:  ");
    for (i = 0; i < IP_ADD_LENGTH; i++)
    {
        snprintf(str, sizeof(str), "%"PRIu8, ip[i]);
        putsUart0(str);
        if (i < IP_ADD_LENGTH-1)
            putcUart0('.');
    }
    putcUart0('\n');



    // Print TCP state message
    char tcpMsg[50];
    strcpy(tcpMsg, "  TCP:   ");
    strcat(tcpMsg, state_names[s.state]);
    putsUart0(tcpMsg);
    putcUart0('\n');

    // Print MQTT state message
    char mqttMsg[50];
    strcpy(mqttMsg, "  MQTT:  ");
    strcat(mqttMsg, mqtt_state_names[mqttStates]);
    putsUart0(mqttMsg);
    putcUart0('\n');

}

void displayConnectionInfo()
{
    uint8_t i;
    char str[10];
    uint8_t mac[6];
    uint8_t ip[4];
    getEtherMacAddress(mac);
    putsUart0("  HW:    ");
    for (i = 0; i < HW_ADD_LENGTH; i++)
    {
        snprintf(str, sizeof(str), "%02"PRIu8, mac[i]);
        putsUart0(str);
        if (i < HW_ADD_LENGTH-1)
            putcUart0(':');
    }
    putcUart0('\n');
    getIpAddress(ip);
    putsUart0("  IP:    ");
    for (i = 0; i < IP_ADD_LENGTH; i++)
    {
        snprintf(str, sizeof(str), "%"PRIu8, ip[i]);
        putsUart0(str);
        if (i < IP_ADD_LENGTH-1)
            putcUart0('.');
    }
    putsUart0(" (static)");
    putcUart0('\n');
    getIpSubnetMask(ip);
    putsUart0("  SN:    ");
    for (i = 0; i < IP_ADD_LENGTH; i++)
    {
        snprintf(str, sizeof(str), "%"PRIu8, ip[i]);
        putsUart0(str);
        if (i < IP_ADD_LENGTH-1)
            putcUart0('.');
    }
    putcUart0('\n');
    getIpGatewayAddress(ip);
    putsUart0("  GW:    ");
    for (i = 0; i < IP_ADD_LENGTH; i++)
    {
        snprintf(str, sizeof(str), "%"PRIu8, ip[i]);
        putsUart0(str);
        if (i < IP_ADD_LENGTH-1)
            putcUart0('.');
    }
    putcUart0('\n');
    getIpDnsAddress(ip);
    putsUart0("  DNS:   ");
    for (i = 0; i < IP_ADD_LENGTH; i++)
    {
        snprintf(str, sizeof(str), "%"PRIu8, ip[i]);
        putsUart0(str);
        if (i < IP_ADD_LENGTH-1)
            putcUart0('.');
    }
    putcUart0('\n');
    getIpTimeServerAddress(ip);
    putsUart0("  Time:  ");
    for (i = 0; i < IP_ADD_LENGTH; i++)
    {
        snprintf(str, sizeof(str), "%"PRIu8, ip[i]);
        putsUart0(str);
        if (i < IP_ADD_LENGTH-1)
            putcUart0('.');
    }
    putcUart0('\n');
    getIpMqttBrokerAddress(ip);
    putsUart0("  MQTT:  ");
    for (i = 0; i < IP_ADD_LENGTH; i++)
    {
        snprintf(str, sizeof(str), "%"PRIu8, ip[i]);
        putsUart0(str);
        if (i < IP_ADD_LENGTH-1)
            putcUart0('.');
    }
    putcUart0('\n');
    if (isEtherLinkUp())
        putsUart0("Link is up\n");
    else
        putsUart0("Link is down\n");
}

void readConfiguration()
{
    uint32_t temp;
    uint8_t* ip;

    temp = readEeprom(EEPROM_IP);
    if (temp != EEPROM_ERASED)
    {
        ip = (uint8_t*)&temp;
        setIpAddress(ip);
    }
    temp = readEeprom(EEPROM_SUBNET_MASK);
    if (temp != EEPROM_ERASED)
    {
        ip = (uint8_t*)&temp;
        setIpSubnetMask(ip);
    }
    temp = readEeprom(EEPROM_GATEWAY);
    if (temp != EEPROM_ERASED)
    {
        ip = (uint8_t*)&temp;
        setIpGatewayAddress(ip);
    }
    temp = readEeprom(EEPROM_DNS);
    if (temp != EEPROM_ERASED)
    {
        ip = (uint8_t*)&temp;
        setIpDnsAddress(ip);
    }
    temp = readEeprom(EEPROM_TIME);
    if (temp != EEPROM_ERASED)
    {
        ip = (uint8_t*)&temp;
        setIpTimeServerAddress(ip);
    }
    temp = readEeprom(EEPROM_MQTT);
    if (temp != EEPROM_ERASED)
    {
        ip = (uint8_t*)&temp;
        setIpMqttBrokerAddress(ip);
    }
}

#define MAX_CHARS 80
char strInput[MAX_CHARS+1];
char* token;
uint8_t count = 0;

uint8_t asciiToUint8(const char str[])
{
    uint8_t data;
    if (str[0] == '0' && tolower(str[1]) == 'x')
        sscanf(str, "%hhx", &data);
    else
        sscanf(str, "%hhu", &data);
    return data;
}

void processShell()
{


    bool end;
    char c;
    uint8_t i;
    uint8_t ip[IP_ADD_LENGTH];
    uint32_t* p32;

    if (kbhitUart0())
    {
        c = getcUart0();

        end = (c == 13) || (count == MAX_CHARS);
        if (!end)
        {
            if ((c == 8 || c == 127) && count > 0)
                count--;
            if (c >= ' ' && c < 127)
                strInput[count++] = c;
        }
        else
        {
            strInput[count] = '\0';
            count = 0;
            token = strtok(strInput, " ");
            if (strcmp(token, "ifconfig") == 0)
            {
                displayConnectionInfo();
            }

            if (strcmp(token, "reboot") == 0)
            {
                NVIC_APINT_R = NVIC_APINT_VECTKEY | NVIC_APINT_SYSRESETREQ;
            }
            if (strcmp(token, "set") == 0)
            {
                token = strtok(NULL, " ");
                if (strcmp(token, "ip") == 0)
                {
                    for (i = 0; i < IP_ADD_LENGTH; i++)
                    {
                        token = strtok(NULL, " .");
                        ip[i] = asciiToUint8(token);
                    }
                    setIpAddress(ip);
                    p32 = (uint32_t*)ip;
                    writeEeprom(EEPROM_IP, *p32);
                }
                if (strcmp(token, "sn") == 0)
                {
                    for (i = 0; i < IP_ADD_LENGTH; i++)
                    {
                        token = strtok(NULL, " .");
                        ip[i] = asciiToUint8(token);
                    }
                    setIpSubnetMask(ip);
                    p32 = (uint32_t*)ip;
                    writeEeprom(EEPROM_SUBNET_MASK, *p32);
                }
                if (strcmp(token, "gw") == 0)
                {
                    for (i = 0; i < IP_ADD_LENGTH; i++)
                    {
                        token = strtok(NULL, " .");
                        ip[i] = asciiToUint8(token);
                    }
                    setIpGatewayAddress(ip);
                    p32 = (uint32_t*)ip;
                    writeEeprom(EEPROM_GATEWAY, *p32);
                }
                if (strcmp(token, "dns") == 0)
                {
                    for (i = 0; i < IP_ADD_LENGTH; i++)
                    {
                        token = strtok(NULL, " .");
                        ip[i] = asciiToUint8(token);
                    }
                    setIpDnsAddress(ip);
                    p32 = (uint32_t*)ip;
                    writeEeprom(EEPROM_DNS, *p32);
                }
                if (strcmp(token, "time") == 0)
                {
                    for (i = 0; i < IP_ADD_LENGTH; i++)
                    {
                        token = strtok(NULL, " .");
                        ip[i] = asciiToUint8(token);
                    }
                    setIpTimeServerAddress(ip);
                    p32 = (uint32_t*)ip;
                    writeEeprom(EEPROM_TIME, *p32);
                }
                if (strcmp(token, "mqtt") == 0)
                {
                    for (i = 0; i < IP_ADD_LENGTH; i++)
                    {
                        token = strtok(NULL, " .");
                        ip[i] = asciiToUint8(token);
                    }
                    setIpMqttBrokerAddress(ip);
                    p32 = (uint32_t*)ip;
                    writeEeprom(EEPROM_MQTT, *p32);
                }


            }
            if (strcmp(token, "connect") == 0)
            {
                sendArpFlag = 1;

            }
            if (strcmp(token, "disconnect") == 0)
            {
                sendMqttDisConnFlag = 1;
            }
            if (strcmp(token, "status") == 0)
            {
                displayStatusInfo();

            }
            if (strcmp(token, "pub") == 0)
            {

                pubTopic = strtok(NULL, " ");
                pubData = strtok(NULL, "");

                mqttPubFlag = 1;

            }
            if (strcmp(token, "sub") == 0)
            {

                subTopic = strtok(NULL, " ");

                mqttSubFlag = 1;

            }
            if (strcmp(token, "unsub") == 0)
            {

                unsubTopic = strtok(NULL, " ");

                mqttUnsubFlag = 1;

            }

            if (strcmp(token, "help") == 0)
            {
                putsUart0("Commands:\r");
                putsUart0("  ifconfig\r");
                putsUart0("  reboot\r");
                putsUart0("  set ip|gw|dns|time|mqtt|sn w.x.y.z\r");
            }
        }
    }
}

uint32_t arraySize(void* array, uint32_t elementSize, uint32_t numElements) {
    return elementSize * numElements;
}


void checkPending(void)
{
    if(sendArpFlag)
    {

        //Send ARP request to obtain remote ip
        sendArpRequest(data, local_ip, remote_ip);
        sendArpFlag = 0;

    }
    if(sendSynFlag)
    {

        sendTcpMessage(data, s, SYN , NULL, 0);
        sendSynFlag = 0;
        s.state = SYN_SENT;

    }
    if(sendAckFlag && s.state ==  SYN_SENT)
    {

        sendTcpMessage(data, s, ACK , NULL, 0);
        sendAckFlag = 0;
        sendMqttConnFlag = 1;
        s.state = ESTABLISHED;


    }
    if(sendMqttConnFlag && s.state == ESTABLISHED)
    {

        mqttConnectMessage(data, s, 0x0018,datas, 0);
        sendMqttConnFlag = 0;
        mqttStates = CONNECTING;

    }

    if(sendMqttAckFlag && mqttStates == CONNECTING)
    {

        sendMqttConnectAck(data,s,NULL,0);
        sendMqttAckFlag = 0;

        mqttStates = CONNECTED;

    }
    if(sendMqttDisConnFlag && mqttStates == CONNECTED)
    {


        mqttDisConnectMessage(data, s, PSH | ACK, datas, 0);
        sendMqttDisConnFlag = 0;
        disFinAckResp = 1;

        s.state = CLOSED;
        mqttStates = DISCONNECTING;

    }
    if(mqttPubFlag && mqttStates == CONNECTED)
    {

        mqttPublishMessage(data, s, pubTopic, pubData);
        mqttPubFlag = 0;

    }
    if(mqttSubFlag && mqttStates == CONNECTED)
    {

        mqttSubscribeMessage(data, s, subTopic);
        mqttSubFlag = 0;

    }
    if(mqttUnsubFlag)
    {

        mqttUnsubscribeMessage(data, s, unsubTopic);
        mqttUnsubFlag = 0;
        putsUart0("Made it here - checking\n");
    }
}
// Main
//-----------------------------------------------------------------------------

// Max packet is calculated as:
// Ether frame header (18) + Max MTU (1500) + CRC (4)

int main(void){
    //uint8_t* udpData;

    // Init controller
    initHw();

    // Setup UART0
    initUart0();
    setUart0BaudRate(115200, 40e6);

    // Init timer
    initTimer();

    // Init ethernet interface (eth0)
    // Use the value x from the spreadsheet
    //putsUart0("\nStarting eth0\n");
    initEther(ETHER_UNICAST | ETHER_BROADCAST | ETHER_HALFDUPLEX);
    setEtherMacAddress(2, 3, 4, 5, 6, 102);

    // Init EEPROM
    initEeprom();
    readConfiguration();

    setPinValue(GREEN_LED, 1);
    waitMicrosecond(100000);
    setPinValue(GREEN_LED, 0);
    waitMicrosecond(100000);

    // Main Loop
    // RTOS and interrupts would greatly improve this code,
    // but the goal here is simplicity
    while (true)
    {
        getIpAddress(local_ip);
        getIpMqttBrokerAddress(remote_ip);
        // Put terminal processing here
        processShell();

        checkPending();

        // Packet processing
        if (isEtherDataAvailable())
        {
            if (isEtherOverflow())
            {
                setPinValue(RED_LED, 1);
                waitMicrosecond(100000);
                setPinValue(RED_LED, 0);
            }

            // Get packet
            getEtherPacket(data, MAX_PACKET_SIZE);

            // Handle ARP request
            if (isArpRequest(data))
            {
                sendArpResponse(data);
            }
            if(isArpResponse(data) && s.state == CLOSED){

                s.state = LISTEN;

                getTcpMessageSocket(data, &s);
                sendSynFlag = 1;

            }
            // Handle IP datagram
            if (isIp(data))
            {
            	if (isIpUnicast(data))
            	{
                    // Handle ICMP ping request
                    if (isPingRequest(data))
                    {
                        sendPingResponse(data);

                    }
                    // Handle TCP datagram
                    if (isTcp(data)){

                        uint8_t *tcpData;

                        tcpData = getTcpData(data, &s);

                        firewall(data, MAX_PACKET_SIZE, &s, whitelist, NUM_WHITELIST_ENTRIES); // Call firewall function

                        if(tcpIsAckSyn(data, &s) && s.state == SYN_SENT){ // Ack for TCP 3-way

                            sendAckFlag = 1;

                        }
                        if(tcpIsFinAck(data, &s) && mqttStates == DISCONNECTING && disFinAckResp){

                            sendTcpMessage(data, s, FIN |ACK , NULL, 0);

                            mqttStates = DISCONNECTED;
                            disFinAckResp = 0;

                        }
                        if(tcpIsMQTTCONNACK(data, &s) && mqttStates == CONNECTING){ // Ack for CONNACK

                            sendMqttAckFlag = 1;
                            sendTcpMessage(data, s, ACK , NULL, 0);
                            mqttStates = CONNECTED;


                        }
                        if(tcpIsMQTTSUBACK(data, &s) && mqttStates == CONNECTED){ // Ack for Sub

                            sendTcpMessage(data, s, ACK , NULL, 0);
                            subTopic = NULL;

                        }
                        if(tcpIsMQTTUNSUBACK(data, &s) && mqttStates == CONNECTED){ // Ack for Sub

                            sendTcpMessage(data, s, ACK , NULL, 0);
                            subTopic = NULL;

                        }
                        if(tcpIsMQTTPUBLISH(data, &s) && mqttStates == CONNECTED){ // Ack for Sub

                            sendTcpMessage(data, s, ACK , NULL, 0);

                            extractMQTTPayload(data, &s);

                        }
                    }
                     //Handle UDP datagram
                    if (isUdp(data))
                    {
                        uint8_t *udpData;
                        udpData = getUdpData(data);
                        if (strcmp((char*)udpData, "on") == 0)
                            setPinValue(GREEN_LED, 1);
                        if (strcmp((char*)udpData, "off") == 0)
                            setPinValue(GREEN_LED, 0);
                        getUdpMessageSocket(data, &s);
                        sendUdpMessage(data, s, (uint8_t*)"Received", 9);
                    }
                }
            }
        }
    }
}
