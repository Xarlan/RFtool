/*
 * wifi.h
 *
 *  Created on: Jul 9, 2018
 *      Author: xarlan
 */

#include "stdint.h"

#ifndef WIFI_H_
#define WIFI_H_

#define SIZE_RAW_802_11		2500


/*
https://networkengineering.stackexchange.com/questions/32970/what-is-the-802-11-mtu
The maximum 802.11 MTU is 2304 bytes
The maximum 802.11 MTU is 2304 bytes
WEP : 2304 + 34 + 8 = 2346 bytes
WPA (TKIP) : 2304 + 34 + 20 = 2358 bytes
WPA2 (CCMP) : 2304 + 34 + 16 = 2354 bytes
*/
typedef struct {
					uint16_t	len_pkt;
					uint8_t		pkt[SIZE_RAW_802_11];
				} wireshark_802_11_t;



#endif /* WIFI_H_ */
