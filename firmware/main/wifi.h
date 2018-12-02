/*
 * wifi.h
 *
 *  Created on: Jul 9, 2018
 *      Author: xarlan
 */

#include "stdint.h"

#ifndef WIFI_H_
#define WIFI_H_




typedef struct {
					wifi_promiscuous_pkt_type_t type;
					wifi_promiscuous_pkt_t 		rawPkt_802_11[2358];		// The maximum 802.11 MTU is 2304 bytes
				} raw_802_11_t;												// WEP : 2304 + 34 + 8 = 2346 bytes
																			// WPA (TKIP) : 2304 + 34 + 20 = 2358 bytes
																			// WPA2 (CCMP) : 2304 + 34 + 16 = 2354 bytes

#endif /* WIFI_H_ */
