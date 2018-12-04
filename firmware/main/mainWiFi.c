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
#include "wifi.h"



xQueueHandle	qRawWifiPkt;


static esp_err_t event_handler(void *ctx, system_event_t *event)
{
    switch (event->event_id) {
        case SYSTEM_EVENT_STA_START:
        	printf("**** 1 ******\n");
//            ESP_LOGI(TAG, "SYSTEM_EVENT_STA_START");
//            ESP_ERROR_CHECK(esp_wifi_connect());
            break;
        case SYSTEM_EVENT_STA_GOT_IP:
        	printf("**** 2 ******\n");
//            ESP_LOGI(TAG, "SYSTEM_EVENT_STA_GOT_IP");
//            ESP_LOGI(TAG, "Got IP: %s\n",
//                     ip4addr_ntoa(&event->event_info.got_ip.ip_info.ip));
            break;
        case SYSTEM_EVENT_STA_DISCONNECTED:
        	printf("**** 3 ******\n");
//            ESP_LOGI(TAG, "SYSTEM_EVENT_STA_DISCONNECTED");
//            ESP_ERROR_CHECK(esp_wifi_connect());
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
//void vUartTask(void *pvParameters)
//{
//	// configure the UART0 controller
//	uart_config_t uart_cfg = {
//								.baud_rate = 115200,
//								.data_bits = UART_DATA_8_BITS,
//								.parity    = UART_PARITY_DISABLE,
//								.stop_bits = UART_STOP_BITS_1,
//								.flow_ctrl = UART_HW_FLOWCTRL_DISABLE
//							 };
//
//	ESP_ERROR_CHECK(uart_param_config(UART_NUM_0, &uart_cfg));
//
//	ESP_ERROR_CHECK(uart_set_pin(UART_NUM_0, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
//
//	ESP_ERROR_CHECK(uart_driver_install(UART_NUM_0, 1024, 0, 0, NULL, 0));
//
//	printf("UART Ok\n");
//
//	wireshark_802_11_t raw_wifi_pkt;
//	portBASE_TYPE xStatus;
//
//	while( 1 )
//	{
//		xStatus = xQueueReceive(qRawWifiPkt, &raw_wifi_pkt, 100/portTICK_RATE_MS);
//		if (xStatus == pdPASS)
//		{
//			printf("len pkt = %d\n", raw_wifi_pkt.len_pkt);
//		}
//
//
//		uart_write_bytes(UART_NUM_0, "*** Ready!\r\n ***", 8);
//		vTaskDelay(1000 / portTICK_PERIOD_MS);
//
//	}
//	vTaskDelete( NULL );
//}


/******************************************************************************
* 						Callback function for 802.11                      						  *
*******************************************************************************/
void sniffer_wifi(void *buff, wifi_promiscuous_pkt_type_t type)
{
	wifi_promiscuous_pkt_t *rawPkt_802_11 = (wifi_promiscuous_pkt_t *)buff;
//	switch(type)
//	{
//		case WIFI_PKT_MGMT:
//			printf("Type pkt = 'MGMT'\n");
//			printf("%d \n", rawPkt_802_11->rx_ctrl.sig_len);
//			break;
//
//		case WIFI_PKT_CTRL:
//			printf("Type pkt = 'CTRL'\n");
//			printf("%d \n", rawPkt_802_11->rx_ctrl.sig_len);
//			break;
//
//		case WIFI_PKT_DATA:
//			printf("Type pkt = 'DATA'\n");
//			printf("%d \n", rawPkt_802_11->rx_ctrl.sig_len);
//			uart_write_bytes(UART_NUM_0, "*** Ready!\r\n ***", 8);
//			break;
//
//		case WIFI_PKT_MISC:
//			printf("Type pkt = 'MIMO'\n");
//			printf("%d \n", rawPkt_802_11->rx_ctrl.sig_len);
//			break;
//
//		default:
//			printf("Unknown pkt type\n");
//			printf("%d \n", rawPkt_802_11->rx_ctrl.sig_len);
//	}

//	printf("\n\nChannel = %d", rawPkt_802_11->rx_ctrl.channel);
//	printf("len wifi pkt = %d\n", rawPkt_802_11->rx_ctrl.sig_len);
//	printf("type pkt %d\n\n", (int)type);

//	int len_pkt = rawPkt_802_11->rx_ctrl.sig_len;

//	uart_write_bytes(UART_NUM_0, (char *) &len_pkt, 2);
//	uart_write_bytes(UART_NUM_0, "\n", 1);
	uart_write_bytes(UART_NUM_0, (char*) rawPkt_802_11->payload, rawPkt_802_11->rx_ctrl.sig_len);
	uart_write_bytes(UART_NUM_0, "\n", 1);

}


/******************************************************************************
* 						Main() application                          									  *
*******************************************************************************/
void app_main()
{
//	qRawWifiPkt = xQueueCreate(10, 2500);
	uart_config_t uart_cfg = {
								.baud_rate = 115200,
								.data_bits = UART_DATA_8_BITS,
								.parity    = UART_PARITY_DISABLE,
								.stop_bits = UART_STOP_BITS_1,
								.flow_ctrl = UART_HW_FLOWCTRL_DISABLE
							 };
	ESP_ERROR_CHECK(uart_param_config(UART_NUM_0, &uart_cfg));
	ESP_ERROR_CHECK(uart_set_pin(UART_NUM_0, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
	ESP_ERROR_CHECK(uart_driver_install(UART_NUM_0, 1024, 0, 0, NULL, 0));
//	printf("UART0 init Ok\n");

//	xTaskCreate(vUartTask, "UartTask", 2048, NULL, 1, NULL);

	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	wifi_country_t wifi_country = {
									.cc="CN",
									.schan=1,
									.nchan=13,
									.policy=WIFI_COUNTRY_POLICY_AUTO
								  };

	nvs_flash_init();
	tcpip_adapter_init();

//	qRawWifiPkt = xQueueCreate(5, sizeof(wireshark_802_11_t));
//	if (qRawWifiPkt != NULL)
//	{
		ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));

		esp_wifi_init(&cfg);
		esp_wifi_set_country(&wifi_country);
		esp_wifi_set_storage(WIFI_STORAGE_RAM);
		esp_wifi_set_mode(WIFI_MODE_NULL);

		esp_wifi_start();
		esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
		esp_wifi_set_promiscuous(true);
		esp_wifi_set_promiscuous_rx_cb(&sniffer_wifi);
//	}
//	else
//	{
//		printf("Can't run task\n");
//	}

}

