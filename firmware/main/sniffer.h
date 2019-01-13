/*
 * sniffer.h
 *
 *  Created on: Dec 1, 2018
 *      Author: xarlan
 */

#ifndef SNIFFER_H_
#define SNIFFER_H_

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


#endif /* SNIFFER_H_ */
