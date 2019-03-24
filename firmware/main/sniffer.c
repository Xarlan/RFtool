/*
 * sniffer.c
 *
 *  Created on: Mar 24, 2019
 *      Author: xarlan
 */

// Wi-Fi component
#include "esp_wifi_types.h"
#include "esp_wifi.h"

#include "sniffer.h"


char* getAuthModeName(wifi_auth_mode_t auth_mode)
{
	char *names[] = {"OPEN", "WEP", "WPA PSK", "WPA2 PSK", "WPA WPA2 PSK", "MAX"};

	return names[auth_mode];
}


/******************************************************************************
* 						Set mode for Wi-Fi			                  		  *
*******************************************************************************/
void pwn_esp_wifi_set_mode(wifi_mode_t mode)
{
	ESP_ERROR_CHECK(esp_wifi_stop());
	ESP_ERROR_CHECK(esp_wifi_set_mode(mode));
	ESP_ERROR_CHECK(esp_wifi_start());
}
