/*
 * 802_11.h
 *
 *  Created on: Dec 7, 2018
 *      Author: xarlan
 */

#ifndef MAIN_802_11_H_
#define MAIN_802_11_H_

#define ESP32_HARDWARE_RX_BUFFER_BYTE		1600		// Size in byte of hardware RX buffer for 802.11
														// 1600 is limitation on ESP32

/****************************************
 * 	   MAC Header -> Frame Control		*
 ****************************************/
typedef struct {
				 unsigned PROTOCOL_VERSION	: 2;
				 unsigned TYPE				: 2;
				 unsigned SUBTYPE			: 4;
				 unsigned TO_DS				: 1;
				 unsigned FROM_DS			: 1;
				 unsigned MORE_FRAG			: 1;
				 unsigned RETRY				: 1;
				 unsigned PWR_MGMT			: 1;
				 unsigned MORE_DATA			: 1;
				 unsigned PROT_FRAME		: 1;
				 unsigned ORDER				: 1;
				} mac_hdr_frame_ctrl_t;


/****************************************
 * 	   	MAC Header 						*
 ****************************************/
typedef struct {
				 mac_hdr_frame_ctrl_t 		FRAME_CONTROL;
				 uint16_t					DURATION_ID;
				 uint8_t 					MAC_ADDR1[6]; 	/* receiver address */
				 uint8_t 					MAC_ADDR2[6]; 	/* sender address */
				 uint8_t 					MAC_ADDR3[6]; 	/* filtering address */
				 uint16_t					SEQUENCE_CTRL;
				 uint8_t 					MAC_ADDR4[6]; 	/* optional */
				 uint16_t					QOS_CTRL;	  	/* optional, used only in QoS Data frames */
				 uint32_t					HT_CTRL;		/* optional, this field add on 802.11n frame */
				} ieee80211_mac_hdr_t;


/****************************************
 * 	   	MAC Protocol Data Unit			*
 ****************************************/
typedef struct {
				ieee80211_mac_hdr_t		MAC_HDR;
				uint8_t					payload[ESP32_HARDWARE_RX_BUFFER_BYTE - sizeof(ieee80211_mac_hdr_t)];
				} ieee80211_mpdu_t;


/*********************************************************
 * 	   	Parcel struct									 *
 *it is as universal struct to send data to vUartTx task *
 *********************************************************/
typedef struct {
				uint8_t					flag;
				wifi_pkt_rx_ctrl_t		ESP32_RADIO_METADATA;
				ieee80211_mpdu_t		MPDU;
				} parcel_tx_t;



/*
https://networkengineering.stackexchange.com/questions/32970/what-is-the-802-11-mtu
The maximum 802.11 MTU is 2304 bytes
The maximum 802.11 MTU is 2304 bytes
WEP : 2304 + 34 + 8 = 2346 bytes
WPA (TKIP) : 2304 + 34 + 20 = 2358 bytes
WPA2 (CCMP) : 2304 + 34 + 16 = 2354 bytes
*/
//typedef struct {
//					uint16_t	len_pkt;
//					uint8_t		pkt[ESP32_HARDWARE_RX_BUFFER_BYTE];
//				} wireshark_802_11_t;
//
//
//typedef struct {
//				wifi_pkt_rx_ctrl_t		ESP32_RADIO_METADATA;
//				ieee80211_mpdu_t		MPDU;
//				} catch_80211_t;

#endif /* MAIN_802_11_H_ */
