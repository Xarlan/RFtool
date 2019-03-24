/*
 * sniffer.h
 *
 *  Created on: Dec 1, 2018
 *      Author: xarlan
 */

#ifndef SNIFFER_H_
#define SNIFFER_H_

#define SIZE_AMPDU			16000				// size in bytes
												// in real word total size
												// AMPDU = 65535 bytes
												// ESP32 has hardware buffer of 1600 bytes

#define MAX_AP			30						// Max number of AP found

//typedef struct {
//				uint8_t		type_data;
//				uint16_t	len_data;
//				char		data[SIZE_AMPDU];
//				} tx_parcel_t;

//typedef struct {
//				uint8_t		type;
//				uint8_t		length;
//				uint8_t		value[7];
//				} tlv_cmd_t;


/******************************************************************************
* 						UART initialize  	                          		  *
*******************************************************************************/
void init_uart(void);


/******************************************************************************
* 						Wi-Fi initialize  	                          		  *
*******************************************************************************/
void init_wifi(void);



/******************************************************************************
* 						From auth_mode code to string                  		  *
*******************************************************************************/
char* getAuthModeName(wifi_auth_mode_t auth_mode);

/******************************************************************************
* 						Set mode for Wi-Fi			                  		  *
*******************************************************************************/
void pwn_esp_wifi_set_mode(wifi_mode_t mode);

#endif /* SNIFFER_H_ */
