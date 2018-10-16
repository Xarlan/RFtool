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
					wifi_promiscuous_pkt_t 		*rawPkt_802_11;
				} esp32_raw_802_11_t;


#endif /* WIFI_H_ */
