/*
 * pwn.c
 *
 *  Created on: Mar 3, 2019
 *      Author: xarlan
 */

#include "string.h"

// FreeRTOS component
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"

// Wi-Fi component
#include "esp_wifi.h"
#include "esp_wifi_types.h"

// UART driver
#include "driver/uart.h"

#include "nvs_flash.h"
#include "esp_event_loop.h"
#include "esp_event.h"

// Error library
#include "esp_err.h"

// Custom h-files
#include "802_11.h"
#include "sniffer.h"


#define ENABLE_AGREGATION		1				// 0 capture 802.11 and immediately send via uart
												// 1 capture 802.11 frame and analyze it

//#define ENABLE_PROMISC			1

/*
 * What components are used
 */

// settings for UART
#define ESP32_UART_PC				UART_NUM_0
#define ESP32_UART_PC_BAUDRATE		921600

// settings for Wi-Fi
#define WIFI_CHANNEL				5

// settings of size queue
#define SIZE_Q_UART_TX				60

// list of Queue
static xQueueHandle qUartTx;					// this Queue used to receive data from any xTask
												// it used in vUartTx

// ID PARCEL for vUartTx
#define ID_PARCEL_WIFI			0x1
#define ID_PARCEL_GET_SETTINGS	0x2

// id for position in buffer TLV
// [Type][Length][Value]
#define TLV_TYPE				0x0
#define TLV_LENGTH				0x1
#define TLV_VALUE				0x2

//id for cmd from PC
#define ID_CMD_ENABNLE_PROMISC	0x1
#define	ID_CMD_GET				0x2
#define	ID_CMD_SET_CHANNEL		0x3
#define ID_CMD_SET_FILTER		0x4


#define UART_BUFF_RX			128				// size in bytes, receive settings from PC
#define UART_BUFF_TX			2048			// size in bytes, send 802.11 packet to PC
#define UART_CMD_QUEUE			5
#define CMD_TLV_BUFFER			10				// size of buffer where will be stored settings from PC
												// it used TLV format - Type-Length-Value



static esp_err_t event_handler(void *ctx, system_event_t *event)
{
    return ESP_OK;
}


//void print_hex_pkt(uint8_t *pkt, char *show_str, uint16_t len_pkt)
//{
//	printf("\n***\n");
//	printf("%s\n", show_str);
//	for (int i=0; i<len_pkt; i++)
//	{
//		printf("%02X ", pkt[i]);
//	}
//	printf("\n");
//}

/******************************************************************************
* 						UART function										  *
* receive settings from PC via uart											  *
*******************************************************************************/
void vUartRx(void *pvParameters)
{

	uint8_t tlv_cmd[CMD_TLV_BUFFER];
	size_t len_tlv_cmd = 0;
	int rx_bytes;
	parcel_tx_t	parcel;

	uint8_t primary_wifi_channel;
	wifi_second_chan_t second_wifi_channel = WIFI_SECOND_CHAN_NONE;
	wifi_promiscuous_filter_t current_filter_pkt;
	portBASE_TYPE xStatus;
	uint16_t ap_num = MAX_AP;
	wifi_ap_record_t ap_records[MAX_AP];

	wifi_scan_config_t scan_config;
		scan_config.ssid 		= 0;
		scan_config.bssid		= 0;
		scan_config.channel		= 0;
		scan_config.show_hidden	= true;

	while(1)
	{


		uart_get_buffered_data_len(ESP32_UART_PC, &len_tlv_cmd);

		if (len_tlv_cmd > 0)
		{
			rx_bytes = uart_read_bytes(ESP32_UART_PC, tlv_cmd, len_tlv_cmd, 10000/portTICK_RATE_MS);

			if (rx_bytes > 0)
			{
				switch(tlv_cmd[TLV_TYPE])
				{
	/***********************************
	 * Enable/Disable promiscuous mode *
	 **********************************/
					case ID_CMD_ENABNLE_PROMISC:
						/*
						 * Check correct length received cmd
						 */
						if ( tlv_cmd[TLV_LENGTH] == 1)
						{

							switch(tlv_cmd[TLV_VALUE])
							{
								case 0x0:
									esp_wifi_set_promiscuous(false);
									break;

								case 0x1:
									esp_wifi_set_promiscuous(true);
									break;

								default:
									esp_wifi_set_promiscuous(false);
							} /* switch(tlv_cmd[2]) */
						}
						break; /* for case 1 */

	/********************
	 * Request Settings *
	 *******************/
					case ID_CMD_GET:
						/*
						 * Check correct length received cmd
						 */
						if ( tlv_cmd[TLV_LENGTH] == 1)
						{
							switch(tlv_cmd[TLV_VALUE])
							{
								/*
								 * Request Wi-Fi channel
								 */
								case 0x0:
									ESP_ERROR_CHECK(esp_wifi_get_channel(&primary_wifi_channel, &second_wifi_channel));
									parcel.flag = ID_PARCEL_GET_SETTINGS;
									parcel.MPDU.payload[0] = 0x0;
									parcel.MPDU.payload[1] = primary_wifi_channel;
									parcel.ESP32_RADIO_METADATA.sig_len = 2;
									xStatus = xQueueSendFromISR(qUartTx, &parcel, 0);
									break;

								/*
								* Request filter of pkt
								*/
								case 0x1:
									ESP_ERROR_CHECK(esp_wifi_get_promiscuous_filter(&current_filter_pkt));
									parcel.flag = ID_PARCEL_GET_SETTINGS;
									parcel.MPDU.payload[0] = 0x1;
									parcel.MPDU.payload[1] = (uint8_t)(current_filter_pkt.filter_mask & 0xFF000000) >> 24;
									parcel.MPDU.payload[2] = (uint8_t)(current_filter_pkt.filter_mask & 0xFF0000) >> 16;
									parcel.MPDU.payload[3] = (uint8_t)(current_filter_pkt.filter_mask & 0xFF00) >> 8;
									parcel.MPDU.payload[4] = (uint8_t)(current_filter_pkt.filter_mask & 0xFF);
									parcel.ESP32_RADIO_METADATA.sig_len = 5;

//									printf("Current filter %X\n", current_filter_pkt.filter_mask);
									xStatus = xQueueSendFromISR(qUartTx, &parcel, 0);

								/*
								 * ESP32 Scan Wi-Fi
								 */
								case 0x2:
									pwn_esp_wifi_set_mode(WIFI_MODE_STA);

//									printf("Size of struct = %d\n", sizeof(wifi_ap_record_t));
									printf("Start scanning...");
									ESP_ERROR_CHECK(esp_wifi_scan_start(&scan_config, true));
									printf(" completed!\n\n");

									// get the list of APs found in the last scan

									ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&ap_num, ap_records));

									// print the list
									printf("Found %d access points:\n", ap_num);
									printf("\n");
									printf("               SSID              | Channel | RSSI |   Auth Mode \n");
									printf("----------------------------------------------------------------\n");
									for(int i = 0; i < ap_num; i++)
										printf("%32s | %7d | %4d | %12s   %d\n", (char *)ap_records[i].ssid,
																			ap_records[i].primary,
																			ap_records[i].rssi,
																			getAuthModeName(ap_records[i].authmode),
																			ap_records[i].wps);
									printf("----------------------------------------------------------------\n");

									parcel.flag = ID_PARCEL_GET_SETTINGS;
									for(int i = 0; i < ap_num; i++)
									{
										memcpy(parcel.MPDU.payload, &ap_records[i], sizeof(wifi_ap_record_t));
										parcel.ESP32_RADIO_METADATA.sig_len = sizeof(wifi_ap_record_t);
										xStatus = xQueueSendFromISR(qUartTx, &parcel, 0);

									}


									pwn_esp_wifi_set_mode(WIFI_MODE_NULL);
									break;

								default:
									break;
							} /* switch(tlv_cmd[TLV_VALUE]) for case 2 */
						} /* if ( tlv_cmd[TLV_LENGTH] == 1) for case 2*/
						break; /* for case 2 */

	/*********************
	 * Set Wi-Fi channel *
	 ********************/
					case ID_CMD_SET_CHANNEL:
						if ( tlv_cmd[TLV_LENGTH] == 1)
						{
							if ( (tlv_cmd[2] >=1 ) & (tlv_cmd[2] < 14) )
							{
								ESP_ERROR_CHECK(esp_wifi_set_channel(tlv_cmd[2], second_wifi_channel));
							}
						}
						break;

	/*********************
	 * Set Wi-Fi channel *
	 ********************/
					case ID_CMD_SET_FILTER:
						if ( tlv_cmd[TLV_LENGTH] == 1)
						{
							switch(tlv_cmd[TLV_VALUE])
							{
								case 0:
									current_filter_pkt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
									break;

								case 1:
									current_filter_pkt.filter_mask = WIFI_PROMIS_FILTER_MASK_CTRL;
									break;

								case 2:
									current_filter_pkt.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA;
									break;

								case 3:
									current_filter_pkt.filter_mask = WIFI_PROMIS_FILTER_MASK_ALL;
									break;

								default:
									current_filter_pkt.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA;
									break;
							}
							ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&current_filter_pkt));
						}
						break;

					default:
						printf("\n*******\nUnknown cmd\n*****\n");
				}

			} 		/* if (rx_bytes > 0) */

		} 			/* if (len_tlv_cmd > 0) */
	}

	vTaskDelete(NULL);
}

/******************************************************************************
* 						UART function										  *
* Transmit and data to PC via uart
* It can be 802.11 frame, requesting setting, etc							  *
*******************************************************************************/
void vUartTx(void *pvParameters)
{

	portBASE_TYPE xStatus;
	volatile TaskHandle_t *hwnd_task_UartRx;

	hwnd_task_UartRx = (TaskHandle_t *) pvParameters;

	const char * DATA_DELIMITER		 	= "<<<PARCEL>>>";
	const char * FLAG_WIFI_PKT	 		= "<<<WiFi>>>";
	const char * FLAG_REQ_SETTINGS		= "<<<RSTG>>>";
//	const char * FLAG_ERROR			= "<<<Errr>>>";

	parcel_tx_t	parcel;
	uint16_t len_802_11 = 0;
	uint32_t timestamp_esp32 = 0;
	uint8_t *pkt;

	uart_write_bytes(ESP32_UART_PC, DATA_DELIMITER, 12);	// 12 - strlen("<<<PARCEL>>>")
															// this transfer is using that on PC side
															// correct capture and analyze data from ESP32


	while (1)
	{
		xStatus = xQueueReceive(qUartTx, &parcel, 0);
		if (xStatus == pdPASS)
		{

			switch (parcel.flag)
			{
				/*
				 * The parcel receive from cb_promiscuos_80211 function
				 */
				case ID_PARCEL_WIFI:
//					if ( parcel.ESP32_RADIO_METADATA.aggregation == 0 &&
//						 parcel.MPDU.MAC_HDR.FRAME_CONTROL.MORE_FRAG == 0)
//					{
						pkt = calloc(parcel.ESP32_RADIO_METADATA.sig_len, sizeof(uint8_t));

						if (pkt != NULL)
						{
							memcpy(pkt, &parcel.MPDU.MAC_HDR.FRAME_CONTROL, 2);
							memcpy(pkt + 2, &parcel.MPDU.payload, parcel.ESP32_RADIO_METADATA.sig_len - 2);

//							print_hex_pkt(pkt, "UART TX:", parcel.ESP32_RADIO_METADATA.sig_len);
//							printf("\n*********************************\n");
//							esp_wifi_set_promiscuous(true);

							len_802_11 = (uint16_t) parcel.ESP32_RADIO_METADATA.sig_len;
							timestamp_esp32 = (uint32_t) parcel.ESP32_RADIO_METADATA.timestamp;

							uart_write_bytes(ESP32_UART_PC, FLAG_WIFI_PKT, 10);

							uart_write_bytes(ESP32_UART_PC, (char *) &len_802_11, 2);
							uart_write_bytes(ESP32_UART_PC, (char *) &timestamp_esp32, 4);
							uart_write_bytes(ESP32_UART_PC, (char *) pkt, parcel.ESP32_RADIO_METADATA.sig_len);

							uart_write_bytes(ESP32_UART_PC, DATA_DELIMITER, 12);

						} /* if (pkt != NULL) */

						free(pkt);
//					} /* conditional of compleate frame */
						break;

				case ID_PARCEL_GET_SETTINGS:
					uart_write_bytes(ESP32_UART_PC, FLAG_REQ_SETTINGS, 10);

					uart_write_bytes(ESP32_UART_PC, (char *) parcel.MPDU.payload, parcel.ESP32_RADIO_METADATA.sig_len);

					uart_write_bytes(ESP32_UART_PC, DATA_DELIMITER, 12);

					break;



			} /* switch (parcel.flag) */


//			uart_write_bytes(ESP32_UART_PC, DATA_DELIMITER, 12);

		}	/* if (xStatus == pdPASS) */

//		if (xStatus == errQUEUE_EMPTY)
//		{
//#if ENABLE_PROMISC
//			esp_wifi_set_promiscuous(true);
//#endif
//		}

	}	/* while(1) */

	vTaskDelete(NULL);
}


/******************************************************************************
* 						Callback function for 802.11                      	  *
*******************************************************************************/
void cb_promiscuous_80211(void *buff, wifi_promiscuous_pkt_type_t type)
{
	portBASE_TYPE xStatus;
	wifi_promiscuous_pkt_t *capture_802_11 = (wifi_promiscuous_pkt_t *)buff;

	if (capture_802_11->rx_ctrl.rx_state == 0)										// state of the packet.
																					// 0: no error;
																					// others: error numbers which are not public
	{
//		uint8_t ptr_payload = 24;			// MAC header:
//											//   2 bytes - FC
//											//   2 bytes - Duration
//											//   6 bytes - MAC ADDR1
//											//   6 bytes - MAC ADDR2
//											//   6 bytes - MAC ADDR3
//											//   2 bytes - SEQ CONTROL
//											//	 6 bytes - MAC ADDR4 - optional
//											//   2 bytes - QoS		 - optional
//											//	 4 bytes - HT CTRL	 - optional

		uint16_t frame_control;
		parcel_tx_t raw_802_11;

		frame_control =  (uint16_t) capture_802_11->payload[0];
		frame_control |= (uint16_t) capture_802_11->payload[1] << 8;

		raw_802_11.flag = ID_PARCEL_WIFI;				// 0x1 - self ID that this parcel send from cb_promiscuous_80211

		memcpy(&raw_802_11.MPDU.MAC_HDR.FRAME_CONTROL, &frame_control, 2);

		memcpy(&raw_802_11.ESP32_RADIO_METADATA, &capture_802_11->rx_ctrl, sizeof(wifi_pkt_rx_ctrl_t));

		memcpy(raw_802_11.MPDU.payload, &capture_802_11->payload[2], capture_802_11->rx_ctrl.sig_len - 2);

//		print_hex_pkt(capture_802_11->payload, "cb function:", (uint16_t) capture_802_11->rx_ctrl.sig_len);
//		esp_wifi_set_promiscuous(false);


		xStatus = xQueueSendFromISR(qUartTx, &raw_802_11, 0);

		if (xStatus == errQUEUE_FULL)
		{
//			esp_wifi_set_promiscuous(false);

			printf("Can't create UART-Rx task\n");
			printf("ESP32 will be reset after 5 sec\n");
			vTaskDelay(5000/ portTICK_PERIOD_MS);
			esp_restart();
		}

	} /* if (capture_802_11->rx_ctrl.rx_state == 0) */

}


/******************************************************************************
* 						Main() application                          		  *
*******************************************************************************/
void app_main()
{
	BaseType_t xReturned;
	TaskHandle_t hwnd_vUartRx = NULL;


	init_uart();
	init_wifi();

	qUartTx = xQueueCreate(SIZE_Q_UART_TX, sizeof(parcel_tx_t));
	if (qUartTx == NULL)
	{
		printf("Can't create queue for xUartTx\n");
		printf("ESP32 will be reset after 3 sec\n");
		vTaskDelay(3000/ portTICK_PERIOD_MS);
		esp_restart();
	}

	xReturned = xTaskCreatePinnedToCore(vUartRx, "UartRx", 8192, NULL, 1, &hwnd_vUartRx, 1);
	if (xReturned != pdPASS)
	{
		printf("Can't create UART-Rx task\n");
		printf("ESP32 will be reset after 3 sec\n");
		vTaskDelay(3000/ portTICK_PERIOD_MS);
		esp_restart();
	}

	xReturned = xTaskCreatePinnedToCore(vUartTx, "UartTx", 8192, (void*)&hwnd_vUartRx, 1, NULL, 1);
	if (xReturned != pdPASS)
	{
		printf("Can't create UART-Tx task\n");
		printf("ESP32 will be reset after 3 sec\n");
		vTaskDelay(3000/ portTICK_PERIOD_MS);
		esp_restart();
	}


	// configure and run the scan process in blocking mode
//	wifi_scan_config_t scan_config = {
//		.ssid = 0,
//		.bssid = 0,
//		.channel = 0,
//        .show_hidden = true
//    };
//	printf("Start scanning...");
//	ESP_ERROR_CHECK(esp_wifi_scan_start(&scan_config, true));
//	printf(" completed!\n");
//	printf("\n");

//	// get the list of APs found in the last scan
//	uint16_t ap_num = 20;
//	wifi_ap_record_t ap_records[20];
//	ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&ap_num, ap_records));
//
//	// print the list
//	printf("Found %d access points:\n", ap_num);
//	printf("\n");
//	printf("               SSID              | Channel | RSSI |   Auth Mode \n");
//	printf("----------------------------------------------------------------\n");
//	for(int i = 0; i < ap_num; i++)
//		printf("%32s | %7d | %4d | %12s\n", (char *)ap_records[i].ssid,
//											ap_records[i].primary,
//											ap_records[i].rssi,
//											getAuthModeName(ap_records[i].authmode));
//	printf("----------------------------------------------------------------\n");



//	   wifi_promiscuous_filter_t filter = {
////			   	   	   	   	   	   	   	   .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL
//			   	   	   	   	   	   	   	   .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA
////										   .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT
////										   .filter_mask = WIFI_PROMIS_FILTER_MASK_CTRL
////										   .filter_mask = WIFI_PROMIS_FILTER_MASK_MISC
//										  };
//		ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));

//		esp_wifi_set_promiscuous(true);

		while ( 1 )
		{

		}

}


/******************************************************************************
* 						UART initialize  	                          		  *
*******************************************************************************/
void init_uart(void)
{
	uart_config_t uart_cfg = {
								.baud_rate = ESP32_UART_PC_BAUDRATE,
								.data_bits = UART_DATA_8_BITS,
								.parity    = UART_PARITY_DISABLE,
								.stop_bits = UART_STOP_BITS_1,
								.flow_ctrl = UART_HW_FLOWCTRL_DISABLE
							 };

	ESP_ERROR_CHECK(uart_param_config(ESP32_UART_PC, &uart_cfg));

	ESP_ERROR_CHECK(uart_set_pin(ESP32_UART_PC, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));

//	ESP_ERROR_CHECK(uart_driver_install(ESP32_UART_PC, 4096, 0, 0, NULL, 0));
	ESP_ERROR_CHECK(uart_driver_install(ESP32_UART_PC, 1024, 4096, 0, NULL, 0));


}


/******************************************************************************
* 						Wi-Fi initialize  	                          		  *
*******************************************************************************/
void init_wifi(void)
{
	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	wifi_country_t wifi_country = {
									.cc="CN",
									.schan=1,
									.nchan=13,
									.policy=WIFI_COUNTRY_POLICY_AUTO
								  };

	nvs_flash_init();
	tcpip_adapter_init();

	ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));

	ESP_ERROR_CHECK(esp_wifi_init(&cfg));

	ESP_ERROR_CHECK(esp_wifi_set_country(&wifi_country));

	ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));

	ESP_ERROR_CHECK(esp_wifi_start());

	ESP_ERROR_CHECK(esp_wifi_set_channel(WIFI_CHANNEL, WIFI_SECOND_CHAN_NONE));

	ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&cb_promiscuous_80211));

}



