#include <string.h>
#include <firewall.h>
#include <tcp.h>
#include <stdio.h>
#include "uart0.h"

void firewall(void* data, uint16_t length, socket* s, whitelist_entry* whitelist, uint8_t num_entries) {
    // Check if incoming traffic matches whitelist
    uint8_t i, match = 0;
    for (i = 0; i < num_entries; i++) {
        if (strncmp((char*)s->remoteIpAddress, (char*)whitelist[i].remoteIpAddr, 4) == 0 && strncmp((char*)s->remoteHwAddress, (char*)whitelist[i].remoteHwAddr, 6) == 0) {

            match = 1;
            break;
        }
    }
    if (!match) {
        char msg[50];
        sprintf(msg, "Blocked traffic from %d.%d.%d.%d:%d\n", s->remoteIpAddress[0], s->remoteIpAddress[1], s->remoteIpAddress[2], s->remoteIpAddress[3], ntohs(s->remotePort));
        putsUart0(msg);
        return;
    }

    char msg[50];
    sprintf(msg, "Forwarded traffic from %d.%d.%d.%d:%d to 127.0.0.1:%d\n", s->remoteIpAddress[0], s->remoteIpAddress[1], s->remoteIpAddress[2], s->remoteIpAddress[3], ntohs(s->remotePort), 1883);
    putsUart0(msg);

}
