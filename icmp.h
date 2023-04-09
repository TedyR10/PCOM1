#ifndef ICMP_H
#define ICMP_H
#include "lib.h"

/*
 * @brief Handles icmp messages for destination unreachable or time exceeded
 *
 * @param m - packet
 * @param type - type of icmp message to send
 */
void icmp(packet *m, int type);

#endif