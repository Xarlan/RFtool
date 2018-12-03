/*
 * wifi.h
 *
 *  Created on: Jul 9, 2018
 *      Author: xarlan
 */

#include "stdint.h"

#ifndef WIFI_H_
#define WIFI_H_

#define SIZE_RAW_802_11		1000


typedef struct {
//					wifi_promiscuous_pkt_type_t type;
					unsigned int				len_pkt;
					unsigned char				pkt[SIZE_RAW_802_11];
//					wifi_promiscuous_pkt_t 		rawPkt_802_11[1500];		// The maximum 802.11 MTU is 2304 bytes
//					wifi_promiscuous_pkt_t 		rawPkt_802_11[2358];		// The maximum 802.11 MTU is 2304 bytes
				} wireshark_802_11_t;												// WEP : 2304 + 34 + 8 = 2346 bytes
																			// WPA (TKIP) : 2304 + 34 + 20 = 2358 bytes
																			// WPA2 (CCMP) : 2304 + 34 + 16 = 2354 bytes
									// https://networkengineering.stackexchange.com/questions/32970/what-is-the-802-11-mtu

#endif /* WIFI_H_ */
