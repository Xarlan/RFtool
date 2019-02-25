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

//// WDT
//#include "soc/timer_group_struct.h"
//#include "soc/timer_group_reg.h"

// Custom h-files
#include "802_11.h"
#include "sniffer.h"


#define ENABLE_AGREGATION		1				// 0 capture 802.11 and immediately send via uart
												// 1 capture 802.11 frame and analyze it

/*
 * What components are used
 */
#define UART_2_PC				UART_NUM_0
//#define UART_2_PC_BAUD_RATE		115200
#define UART_2_PC_BAUD_RATE		921600
#define UART_BUFF_RX			128				// size in bytes, receive settings from PC
#define UART_BUFF_TX			2048			// size in bytes, send 802.11 packet to PC
#define UART_CMD_QUEUE			5
#define CMD_TLV_BUFFER			10				// size of buffer where will be stored settings from PC
												// it used TLV format - Type-Length-Value

#define WIFI_CHANNEL			5


static xQueueHandle q_wifi_uart;
static xQueueHandle q_cmd;						// hwnd of queue, which used to receive cmd from PC
static QueueHandle_t uart0_queue;




//**************
#define EX_UART_NUM UART_NUM_0
#define PATTERN_CHR_NUM    (3)
#define BUF_SIZE (1024)
#define RD_BUF_SIZE (BUF_SIZE)

//**************



static esp_err_t event_handler(void *ctx, system_event_t *event)
{
//    switch (event->event_id) {
//        case SYSTEM_EVENT_STA_START:
//        	printf("**** 1 ******\n");
//            break;
//
//        case SYSTEM_EVENT_STA_GOT_IP:
//        	printf("**** 2 ******\n");
//            break;
//
//        case SYSTEM_EVENT_STA_DISCONNECTED:
//        	printf("**** 3 ******\n");
//            break;
//
//        default:
//            break;
//    }
    return ESP_OK;
}


/******************************************************************************
* 																			  *
* receive settings from PC via uart, used EVENT								  *
*******************************************************************************/
//static void vUartEventSettings(void *pvParameters)
//{
//    uart_event_t event;
//    size_t buffered_size;
//    uint8_t* dtmp = (uint8_t*) malloc(RD_BUF_SIZE);
//
//    while ( 1 )
//    {
//        //Waiting for UART event.
//        if( xQueueReceive(uart0_queue, (void * )&event, (portTickType)portMAX_DELAY) )
//        {
//            bzero(dtmp, RD_BUF_SIZE);
////            ESP_LOGI(TAG, "uart[%d] event:", EX_UART_NUM);
//            switch(event.type)
//            {
//                //Event of UART receving data
//                /*We'd better handler data event fast, there would be much more data events than
//                other types of events. If we take too much time on data event, the queue might
//                be full.*/
//                case UART_DATA:
////                    ESP_LOGI(TAG, "[UART DATA]: %d", event.size);
//                    uart_read_bytes(EX_UART_NUM, dtmp, event.size, portMAX_DELAY);
//                    printf("UART Rx form PC: %s\n", dtmp);
//                    esp_wifi_set_promiscuous(false);
//
////                    ESP_LOGI(TAG, "[DATA EVT]:");
//                    uart_write_bytes(EX_UART_NUM, (const char*) dtmp, event.size);
//                    break;
//
//                default:
////                    ESP_LOGI(TAG, "uart event type: %d", event.type);
//                    break;
//            }
//        }
//    }
//    free(dtmp);
//    dtmp = NULL;
//    vTaskDelete(NULL);
//}

/******************************************************************************
* 						UART function										  *
* receive settings from PC via uart											  *
*******************************************************************************/
void vUartSettings(void *pvParameters)
{

	uint8_t tlv_cmd[CMD_TLV_BUFFER];
//	tlv_cmd_t tlv_cmd;
	size_t len_tlv_cmd;
	int rx_bytes;
	uint8_t current_wifi_channel;

	while(1)
	{
		uart_get_buffered_data_len(UART_2_PC, &len_tlv_cmd);
		rx_bytes = uart_read_bytes(UART_2_PC, tlv_cmd, len_tlv_cmd, 1000/portTICK_RATE_MS);
		if (rx_bytes > 0)
		{
			switch(tlv_cmd[0])
			{
				case 1:
					printf("start/stop sniffer\n");
					break;

				case 2:
					ESP_ERROR_CHECK(esp_wifi_get_channel(&current_wifi_channel, WIFI_SECOND_CHAN_NONE));
					printf("Current channel - %d\n", current_wifi_channel);
			}
		}
	}

	vTaskDelete(NULL);
}

/******************************************************************************
* 						UART function										  *
* get raw 802.11 frame from queue and send it via uart						  *
*******************************************************************************/
void vUartWiFi(void *pvParameters)
{

#if ENABLE_AGREGATION == 0
	wireshark_802_11_t wifi_frame;
	portBASE_TYPE xStatus;

	while( 1 )
	{
//		xStatus = xQueueReceive(q_wifi_uart, &wifi_frame, portMAX_DELAY);
		xStatus = xQueueReceive(q_wifi_uart, &wifi_frame, 0);
		if (xStatus == pdPASS)
		{

			for(int i=0; i<wifi_frame.len_pkt; i++)
			{
				printf("%02X ", wifi_frame.pkt[i]);
			}
			printf("\n\n");

//			uart_write_bytes(UART_NUM_0, (char*) wifi_frame.pkt, wifi_frame.len_pkt);
//			uart_write_bytes(UART_NUM_0, "\n", 1);
		}

		if (xStatus == errQUEUE_EMPTY)
		{
			esp_wifi_set_promiscuous(true);
		}

//		if (xStatus == errQUEUE_FULL)
//		{
//			esp_wifi_set_promiscuous(true);
//			printf("\n\n\nQueue is Full\nPromiscuous mode enable\n");
//		}

	}
	vTaskDelete( NULL );

#else


	wifi2uart_t wifi_frame;
	portBASE_TYPE xStatus;

	const char * WIFI_PKT_LABEL = "<<<WiFi>>>";
	const char * RF_DELIMITER 	= "<<<RfPkt>>>";

	uart_write_bytes(UART_2_PC, RF_DELIMITER, 11);

	while( 1 )
	{
//		xStatus = xQueueReceive(q_wifi_uart, &wifi_frame, portMAX_DELAY);
		xStatus = xQueueReceive(q_wifi_uart, &wifi_frame, 0);
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
																	//	 4 bytes - HT CTRL   - optional

			pkt = calloc(wifi_frame.ESP32_RADIO_METADATA.sig_len, sizeof(uint8_t));

			if (pkt != NULL)
			{

				memcpy(pkt, &wifi_frame.MPDU.MAC_HDR.FRAME_CONTROL, 2);
				memcpy(pkt + 2, &wifi_frame.MPDU.MAC_HDR.DURATION_ID, 2);
				memcpy(pkt + 4, &wifi_frame.MPDU.MAC_HDR.MAC_ADDR1, 6);
				memcpy(pkt + 10, &wifi_frame.MPDU.MAC_HDR.MAC_ADDR2, 6);
				memcpy(pkt + 16, &wifi_frame.MPDU.MAC_HDR.MAC_ADDR3, 6);
				memcpy(pkt + 22, &wifi_frame.MPDU.MAC_HDR.SEQUENCE_CTRL, 2);

				/*
				 * Check TO_DS and FROM_DS
				 * it TO_DS==1, FROM_DS==1, add MAC_ADDR4
				 */
				if (wifi_frame.MPDU.MAC_HDR.FRAME_CONTROL.FROM_DS & wifi_frame.MPDU.MAC_HDR.FRAME_CONTROL.TO_DS)
				{

					memcpy(pkt + len_mac_hdr, &wifi_frame.MPDU.MAC_HDR.MAC_ADDR4, 6);
					len_mac_hdr += 6;
				}

				/*
				 * Check to QoS
				 */
				if ((wifi_frame.MPDU.MAC_HDR.FRAME_CONTROL.SUBTYPE & 0x80) & (wifi_frame.MPDU.MAC_HDR.FRAME_CONTROL.TYPE == WIFI_PKT_DATA))
				{
					memcpy(pkt + len_mac_hdr, &wifi_frame.MPDU.MAC_HDR.QOS_CTRL, 2);
					len_mac_hdr += 2;
				}

				/*
				 * Check HT CTRL
				 */
				if (wifi_frame.ESP32_RADIO_METADATA.sig_mode == 1)
				{
					memcpy(pkt + len_mac_hdr, &wifi_frame.MPDU.MAC_HDR.HT_CTRL, 4);
					len_mac_hdr += 4;
				}

				memcpy(pkt + len_mac_hdr, &wifi_frame.MPDU.payload, wifi_frame.ESP32_RADIO_METADATA.sig_len - len_mac_hdr);

//				printf("\n****\nWi-Fi -> UART:\n");
//				printf("DS = %d   FROM_DS = %d\n", wifi_frame.MPDU.MAC_HDR.FRAME_CONTROL.TO_DS, wifi_frame.MPDU.MAC_HDR.FRAME_CONTROL.FROM_DS);
//				for(int i=0; i<wifi_frame.ESP32_RADIO_METADATA.sig_len; i++)
//				{
//					printf("%02X ", pkt[i]);
//				}


//				if (wifi_frame.ESP32_RADIO_METADATA.aggregation)
//				{
//					printf("Will be send:\n");
//					for (int i=0; i<45; i++)
//					{
//						printf("%02X ", pkt[i]);
//					}
//
//					printf("\n*****************\n\n\n\n");
//				}

				uint16_t len_802_11 = 0;
				uint32_t timestamp_esp32 = 0;

				len_802_11 = (uint16_t) wifi_frame.ESP32_RADIO_METADATA.sig_len;
				timestamp_esp32 = (uint32_t) wifi_frame.ESP32_RADIO_METADATA.timestamp;

				uart_write_bytes(UART_2_PC, WIFI_PKT_LABEL, 10);

				uart_write_bytes(UART_2_PC, (char *) &len_802_11, 2);
				uart_write_bytes(UART_2_PC, (char *) &timestamp_esp32, 4);
				uart_write_bytes(UART_2_PC, (char*) pkt, wifi_frame.ESP32_RADIO_METADATA.sig_len);

				uart_write_bytes(UART_2_PC, RF_DELIMITER, 11);


				free(pkt);
			} 										// end of if (pkt != NULL)
		}											// end of if (xStatus == pdPASS)

		if (xStatus == errQUEUE_EMPTY)
		{
			esp_wifi_set_promiscuous(true);
		}

	}
	vTaskDelete( NULL );
#endif
}



/******************************************************************************
* 						Callback function for 802.11                      	  *
*******************************************************************************/
void sniffer_wifi(void *buff, wifi_promiscuous_pkt_type_t type)
{

/******************************************************************************************************/
/*
 * immediatly send to uart
 */
//	wifi_promiscuous_pkt_t *capture_802_11 = (wifi_promiscuous_pkt_t *)buff;
//	uart_write_bytes(UART_NUM_0, (char*) capture_802_11->payload, capture_802_11->rx_ctrl.sig_len);
//	uart_write_bytes(UART_NUM_0, "\n", 1);
/******************************************************************************************************/


/**************************
 *  direct send to queue  *
 **************************/
#if ENABLE_AGREGATION == 0

	wifi_promiscuous_pkt_t *capture_802_11 = (wifi_promiscuous_pkt_t *)buff;

	wireshark_802_11_t wifi_frame;
	portBASE_TYPE xStatus;

	memcpy(&wifi_frame.pkt, capture_802_11->payload, capture_802_11->rx_ctrl.sig_len);

	wifi_frame.len_pkt = capture_802_11->rx_ctrl.sig_len;

//	xStatus = xQueueSendFromISR(q_wifi_uart, &wifi_frame, NULL);
	xStatus = xQueueSendFromISR(q_wifi_uart, &wifi_frame, 0);

//	if (xStatus == errQUEUE_FULL)
//	{
//		esp_wifi_set_promiscuous(false);
////		printf("\n\n\n\nQueue is full\nPromiscuous mode stop\n");
//	}

#else
	portBASE_TYPE xStatus;
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
											//	 4 bytes - HT CTRL	 - optional

		wifi2uart_t wifi_frame;

		uint16_t frame_control;
		frame_control = (uint16_t)capture_802_11->payload[1] << 8;
		frame_control |=(uint16_t) capture_802_11->payload[0];
		memcpy(&wifi_frame.MPDU.MAC_HDR.FRAME_CONTROL, &frame_control, 2);

		wifi_frame.MPDU.MAC_HDR.DURATION_ID = (uint16_t) capture_802_11->payload[3] << 8;
		wifi_frame.MPDU.MAC_HDR.DURATION_ID |= (uint16_t) capture_802_11->payload[2];

		memcpy(wifi_frame.MPDU.MAC_HDR.MAC_ADDR1, &capture_802_11->payload[4], 6);
		memcpy(wifi_frame.MPDU.MAC_HDR.MAC_ADDR2, &capture_802_11->payload[10], 6);
		memcpy(wifi_frame.MPDU.MAC_HDR.MAC_ADDR3, &capture_802_11->payload[16], 6);

		wifi_frame.MPDU.MAC_HDR.SEQUENCE_CTRL = (uint16_t) capture_802_11->payload[23] << 8;
		wifi_frame.MPDU.MAC_HDR.SEQUENCE_CTRL |= (uint16_t) capture_802_11->payload[22];

		/*
		 * Check TO_DS and FROM_DS bits in MAC_HDR -> Frame Control
		 */
		if (wifi_frame.MPDU.MAC_HDR.FRAME_CONTROL.FROM_DS & wifi_frame.MPDU.MAC_HDR.FRAME_CONTROL.TO_DS)
		{
			memcpy(wifi_frame.MPDU.MAC_HDR.MAC_ADDR4, &capture_802_11->payload[24], 6);
			ptr_payload += 6;
		}

		/*
		 * Check QoS in Data Frame
		 * The 802.11-2007 standard
		 * “The QoS Control field is present in all data frames
		 * in which the QoS subfield of the Subtype field is set to 1.”
		 *
		 * IEEE 802.11-2012
		 * 8.2.4.5.1 QoS Control field structure
		*/
		if (type == WIFI_PKT_DATA && (wifi_frame.MPDU.MAC_HDR.FRAME_CONTROL.SUBTYPE & 0x80) )
		{
			wifi_frame.MPDU.MAC_HDR.QOS_CTRL = (uint16_t) (capture_802_11->payload[ptr_payload + 1] << 8);
			wifi_frame.MPDU.MAC_HDR.QOS_CTRL |= (uint16_t) (capture_802_11->payload[ptr_payload]);
			ptr_payload += 2;
		}

		/*
		 * Check HT Control Field
		 * IEEE 802.11-2012
		 * 8.2.4.6 HT Control field
		 */
		if (capture_802_11->rx_ctrl.sig_mode == 1)
		{
			wifi_frame.MPDU.MAC_HDR.HT_CTRL = (uint32_t) (capture_802_11->payload[ptr_payload + 3] << 24);
			wifi_frame.MPDU.MAC_HDR.HT_CTRL |= (uint32_t) (capture_802_11->payload[ptr_payload + 2] << 16);
			wifi_frame.MPDU.MAC_HDR.HT_CTRL |= (uint32_t) (capture_802_11->payload[ptr_payload + 1] << 8);
			wifi_frame.MPDU.MAC_HDR.HT_CTRL |= (uint32_t) (capture_802_11->payload[ptr_payload]);
			ptr_payload += 4;
		}

		memcpy(wifi_frame.MPDU.payload, &capture_802_11->payload[ptr_payload], capture_802_11->rx_ctrl.sig_len - ptr_payload);

		memcpy(&wifi_frame.ESP32_RADIO_METADATA, &capture_802_11->rx_ctrl, sizeof(wifi_pkt_rx_ctrl_t));

		xStatus = xQueueSendFromISR(q_wifi_uart, &wifi_frame, 0);

		if (xStatus == errQUEUE_FULL)
		{
			esp_wifi_set_promiscuous(false);
		}

	}
#endif
}


/******************************************************************************
* 						Main() application                          		  *
*******************************************************************************/
void app_main()
{

	init_uart();
	init_wifi();

#if ENABLE_AGREGATION == 0
	q_wifi_uart = xQueueCreate(20, sizeof(wireshark_802_11_t));
#else
	q_wifi_uart = xQueueCreate(20, sizeof(wifi2uart_t));
#endif

	if (q_wifi_uart != NULL)
	{
		printf("queue is created\n");
//		xTaskCreate(vUartTask, "UartTask", 8192, NULL, 1, NULL);
		xTaskCreatePinnedToCore(vUartWiFi, "UartWiFi", 8192, NULL, 1, NULL, 1);
//		xTaskCreatePinnedToCore(vUartEventSettings, "UartSettings", 2048, NULL, 12, NULL, 1);

		xTaskCreatePinnedToCore(vUartSettings, "UartSettings", 2048, NULL, 12, NULL, 1);


	   wifi_promiscuous_filter_t filter = {
			   	   	   	   	   	   	   	   .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL
//			   	   	   	   	   	   	   	   .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA
//										   .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT
//										   .filter_mask = WIFI_PROMIS_FILTER_MASK_CTRL
//										   .filter_mask = WIFI_PROMIS_FILTER_MASK_MISC
										  };
		ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));

		esp_wifi_set_promiscuous(true);

		while ( 1 )
		{

		}



	}
	else
	{
		printf("ESP32 will be reset after 3 sec\n");
		vTaskDelay(3000/ portTICK_PERIOD_MS);
		esp_restart();

	}

}


/******************************************************************************
* 						UART initialize  	                          		  *
*******************************************************************************/
void init_uart(void)
{
	uart_config_t uart_cfg = {
								.baud_rate = UART_2_PC_BAUD_RATE,
								.data_bits = UART_DATA_8_BITS,
								.parity    = UART_PARITY_DISABLE,
								.stop_bits = UART_STOP_BITS_1,
								.flow_ctrl = UART_HW_FLOWCTRL_DISABLE
							 };

	ESP_ERROR_CHECK(uart_param_config(UART_2_PC, &uart_cfg));

	ESP_ERROR_CHECK(uart_set_pin(UART_2_PC, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));

	ESP_ERROR_CHECK(uart_driver_install(UART_2_PC, 4096, 0, 0, NULL, 0));

//	ESP_ERROR_CHECK(uart_driver_install(UART_2_PC, UART_BUFF_RX, UART_BUFF_TX, UART_CMD_QUEUE, &q_cmd, 0));
//	ESP_ERROR_CHECK(uart_driver_install(UART_2_PC, UART_BUFF_RX, UART_BUFF_TX, 0, NULL, 0));
//	ESP_ERROR_CHECK(uart_driver_install(UART_2_PC, 64, 64, 0, NULL, 0));
//	ESP_ERROR_CHECK(uart_driver_install(UART_NUM_0, 4096, 0, 0, NULL, 0));

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

	ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&sniffer_wifi));
}
