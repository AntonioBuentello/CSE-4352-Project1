//Antonio Buentello


#ifndef FIREWALL_H
#define FIREWALL_H

#include <stdint.h>
#include "eth0.h"
#include "ip.h"

#define NUM_WHITELIST_ENTRIES 2

typedef struct _whitelist_entry {
    uint8_t remoteIpAddr[4];
    uint8_t remoteHwAddr[6];
} whitelist_entry;


// Define a structure to hold the IP and MAC addresses for whitelisting
typedef struct {
    uint8_t remoteIpAddress[4];
    uint8_t remoteHwAddress[6];
} whitelist_t;

// Define a function to apply the firewall rules
void firewall(void* data, uint16_t length, socket* s, whitelist_entry* whitelist, uint8_t num_entries);

#endif // FIREWALL_H
