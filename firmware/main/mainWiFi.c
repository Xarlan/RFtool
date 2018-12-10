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

// Error library
#include "esp_err.h"

// Custom h-files
#include "802_11.h"


static xQueueHandle q_wifi_uart;


static esp_err_t event_handler(void *ctx, system_event_t *event)
{
    switch (event->event_id) {
        case SYSTEM_EVENT_STA_START:
        	printf("**** 1 ******\n");
            break;

        case SYSTEM_EVENT_STA_GOT_IP:
        	printf("**** 2 ******\n");
            break;

        case SYSTEM_EVENT_STA_DISCONNECTED:
        	printf("**** 3 ******\n");
            break;

        default:
            break;
    }
    return ESP_OK;
}

/******************************************************************************
* 						UART function										  *
* receive raw 802.11 frame and send it via uart								  *
*******************************************************************************/
void vUartTask(void *pvParameters)
{
	// configure the UART0 controller
	uart_config_t uart_cfg = {
								.baud_rate = 115200,
//								.baud_rate = 921600,
								.data_bits = UART_DATA_8_BITS,
								.parity    = UART_PARITY_DISABLE,
								.stop_bits = UART_STOP_BITS_1,
								.flow_ctrl = UART_HW_FLOWCTRL_DISABLE
							 };

	ESP_ERROR_CHECK(uart_param_config(UART_NUM_0, &uart_cfg));
	ESP_ERROR_CHECK(uart_set_pin(UART_NUM_0, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
	ESP_ERROR_CHECK(uart_driver_install(UART_NUM_0, 4096, 0, 0, NULL, 0));


	wifi2uart_t wifi_frame;
	portBASE_TYPE xStatus;

	while( 1 )
	{
//		xStatus = xQueueReceive(q_wifi_uart, &raw_wifi_pkt, portMAX_DELAY);
		xStatus = xQueueReceive(q_wifi_uart, &wifi_frame, portMAX_DELAY);
		if (xStatus == pdPASS)
		{
			uint8_t *pkt;
			uint16_t len_mac_hdr = 24;								// the length of MAC hdr, which include:
																	//   2 bytes - FC
																	//   2 bytes - Duration
																	//   6 bytes - MAC ADDR1
																	//   6 bytes - MAC ADDR2
																	//   6 bytes - MAC ADDR3
																	//   2 bytes - SEQ CONTROL
																	//	 6 bytes - MAC ADDR4 - optional
																	//   2 bytes - QoS		 - optional

			pkt = calloc(wifi_frame.len_mpdu, sizeof(uint8_t));

			memcpy(pkt, &wifi_frame.MPDU.MAC_HDR.FRAME_CONTROL, 2);
			memcpy(pkt + 2, &wifi_frame.MPDU.MAC_HDR.DURATION_ID, 2);
			memcpy(pkt + 4, &wifi_frame.MPDU.MAC_HDR.MAC_ADDR1, 6);
			memcpy(pkt + 10, &wifi_frame.MPDU.MAC_HDR.MAC_ADDR2, 6);
			memcpy(pkt + 16, &wifi_frame.MPDU.MAC_HDR.MAC_ADDR3, 6);
			memcpy(pkt + 22, &wifi_frame.MPDU.MAC_HDR.SEQUENCE_CTRL, 2);

			// Check TO_DS and FROM_DS
			// it TO_DS==1, FROM_DS==1, add MAC_ADDR4
			if (wifi_frame.MPDU.MAC_HDR.FRAME_CONTROL & 0x300)
			{
				printf("MAC_ADDR4, len_mac_hdr = %d\n", len_mac_hdr);
				memcpy(pkt + len_mac_hdr, &wifi_frame.MPDU.MAC_HDR.MAC_ADDR4, 6);
				len_mac_hdr += 6;
			}

			// Check to QoS
			if (wifi_frame.MPDU.MAC_HDR.FRAME_CONTROL & 0x8800)
			{
				memcpy(pkt + len_mac_hdr, &wifi_frame.MPDU.MAC_HDR.QOS_CTRL, 2);
				len_mac_hdr += 2;
			}

			memcpy(pkt + len_mac_hdr, &wifi_frame.MPDU.payload, wifi_frame.len_mpdu - len_mac_hdr);

			printf("Will be send:\n");
			for (int i=0; i<45; i++)
			{
				printf("%02X ", pkt[i]);
			}
			printf("\n\n");


//			uart_write_bytes(UART_NUM_0, (char*) pkt, wifi_frame.len_mpdu);
//			uart_write_bytes(UART_NUM_0, "\n", 1);


			free(pkt);
		}

//		uart_write_bytes(UART_NUM_0, "*** Ready!\r\n ***", 8);
//		vTaskDelay(1000 / portTICK_PERIOD_MS);
		esp_wifi_set_promiscuous(true);

	}
	vTaskDelete( NULL );
}



/******************************************************************************
* 						Callback function for 802.11                      	  *
*******************************************************************************/
void sniffer_wifi(void *buff, wifi_promiscuous_pkt_type_t type)
{
//	wifi_promiscuous_pkt_t *capture_802_11 = (wifi_promiscuous_pkt_t *)buff;
//
//	wireshark_802_11_t wifi_pkt;
//
////	if ( capture_802_11->rx_ctrl.rx_state == 0 && type == WIFI_PKT_MGMT)
//	if ( capture_802_11->rx_ctrl.rx_state == 0)										// state of the packet.
//																					// 0: no error;
//																					// others: error numbers which are not public
//	{
//		wifi_pkt.len_pkt = (uint16_t) capture_802_11->rx_ctrl.sig_len;
//		wifi_pkt.type_pkt = (uint8_t) type;
//		memcpy(wifi_pkt.pkt,capture_802_11->payload, capture_802_11->rx_ctrl.sig_len);
//
//		xQueueSendFromISR(q_wifi_uart, &wifi_pkt, NULL);
////		xStatus = xQueueSendToBack(q_wifi_uart, &wifi_pkt, NULL);
////		if (xStatus != pdPASS)
////		{
////			printf("Could not send to the queue\n");
////			vTaskDelay(3000/ portTICK_PERIOD_MS);
////			esp_restart();
////		}
//	}
//
////	uart_write_bytes(UART_NUM_0, (char *) &len_pkt, 2);
////	uart_write_bytes(UART_NUM_0, "\n", 1);
//
////	uart_write_bytes(UART_NUM_0, (char*) capture_802_11->payload, capture_802_11->rx_ctrl.sig_len);
////	uart_write_bytes(UART_NUM_0, "\n", 1);
//
	wifi_promiscuous_pkt_t *capture_802_11 = (wifi_promiscuous_pkt_t *)buff;

	if ( capture_802_11->rx_ctrl.rx_state == 0)										// state of the packet.
																					// 0: no error;
																					// others: error numbers which are not public
	{
		uint8_t ptr_payload=24;				// MAC header:
											//   2 bytes - FC
											//   2 bytes - Duration
											//   6 bytes - MAC ADDR1
											//   6 bytes - MAC ADDR2
											//   6 bytes - MAC ADDR3
											//   2 bytes - SEQ CONTROL
											//	 6 bytes - MAC ADDR4 - optional
											//   2 bytes - QoS		 - optional
//		ieee80211_mpdu_t wifi_frame;
		wifi2uart_t wifi_frame;

//		wifi_frame.MPDU.MAC_HDR.FRAME_CONTROL = ((uint16_t) capture_802_11->payload[0] << 8) || ((uint16_t) capture_802_11->payload[1]);
		wifi_frame.MPDU.MAC_HDR.FRAME_CONTROL = (uint16_t) capture_802_11->payload[1] << 8;
		wifi_frame.MPDU.MAC_HDR.FRAME_CONTROL |= (uint16_t) capture_802_11->payload[0];

//		wifi_frame.MPDU.MAC_HDR.DURATION_ID   = (uint16_t) (capture_802_11->payload[3] << 8) || capture_802_11->payload[2];
		wifi_frame.MPDU.MAC_HDR.DURATION_ID = (uint16_t) capture_802_11->payload[3] << 8;
		wifi_frame.MPDU.MAC_HDR.DURATION_ID |= (uint16_t) capture_802_11->payload[2];

		memcpy(wifi_frame.MPDU.MAC_HDR.MAC_ADDR1, &capture_802_11->payload[4], 6);
		memcpy(wifi_frame.MPDU.MAC_HDR.MAC_ADDR2, &capture_802_11->payload[10], 6);
		memcpy(wifi_frame.MPDU.MAC_HDR.MAC_ADDR3, &capture_802_11->payload[16], 6);

//		wifi_frame.MPDU.MAC_HDR.SEQUENCE_CTRL = (uint16_t) (capture_802_11->payload[23] << 8) || capture_802_11->payload[22];
		wifi_frame.MPDU.MAC_HDR.SEQUENCE_CTRL = (uint16_t) capture_802_11->payload[23] << 8;
		wifi_frame.MPDU.MAC_HDR.SEQUENCE_CTRL |= (uint16_t) capture_802_11->payload[22];

		// Check TO_DS and FROM_DS bits
		// in MAC_HDR -> Frame Control
		if (wifi_frame.MPDU.MAC_HDR.FRAME_CONTROL & 0x300)
		{
			memcpy(wifi_frame.MPDU.MAC_HDR.MAC_ADDR4, &capture_802_11->payload[24], 6);
			ptr_payload += 6;
		}

		// Check QoS in Data Frame
		// The 802.11-2007 standard
		//    “The QoS Control field is present in all data frames
		//     in which the QoS subfield of the Subtype field is set to 1.”
		if (type == WIFI_PKT_DATA && (wifi_frame.MPDU.MAC_HDR.FRAME_CONTROL & 0x80) )
		{
			printf("Current ptr_payload = %d\n", ptr_payload);
			wifi_frame.MPDU.MAC_HDR.QOS_CTRL = (uint16_t) (capture_802_11->payload[ptr_payload + 1] << 8);
			wifi_frame.MPDU.MAC_HDR.QOS_CTRL |= (uint16_t) (capture_802_11->payload[ptr_payload]);
			ptr_payload += 2;
		}

		memcpy(wifi_frame.MPDU.payload, &capture_802_11->payload[ptr_payload], capture_802_11->rx_ctrl.sig_len - ptr_payload);

		wifi_frame.len_mpdu = capture_802_11->rx_ctrl.sig_len;

		printf("\n");
		printf("Captured pkt, len = %d: \n", capture_802_11->rx_ctrl.sig_len);
//		printf("Frame Control %04X\n",wifi_frame.MPDU.MAC_HDR.FRAME_CONTROL);
		for (int i=0; i<45; i++)
		{
			printf("%02X ", capture_802_11->payload[i]);
		}

		esp_wifi_set_promiscuous(false);

		xQueueSendFromISR(q_wifi_uart, &wifi_frame, NULL);

	}

}


/******************************************************************************
* 						Main() application                          		  *
*******************************************************************************/
void app_main()
{

//	q_wifi_uart = xQueueCreate(50, sizeof(wireshark_802_11_t));
	q_wifi_uart = xQueueCreate(50, sizeof(wifi2uart_t));

	if (q_wifi_uart != NULL)
	{
//		xTaskCreate(vUartTask, "UartTask", 8192, NULL, 1, NULL);
		xTaskCreatePinnedToCore(vUartTask, "UartTask", 8192, NULL, 1, NULL, 1);

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

		esp_wifi_init(&cfg);
		esp_wifi_set_country(&wifi_country);
		esp_wifi_set_storage(WIFI_STORAGE_RAM);
		esp_wifi_set_mode(WIFI_MODE_NULL);

		esp_wifi_start();
		esp_wifi_set_channel(5, WIFI_SECOND_CHAN_NONE);
		esp_wifi_set_promiscuous(true);
		esp_wifi_set_promiscuous_rx_cb(&sniffer_wifi);

	}
	else
	{
		printf("ESP32 will be reset after 3 sec\n");
		vTaskDelay(3000/ portTICK_PERIOD_MS);
		esp_restart();

	}



}
