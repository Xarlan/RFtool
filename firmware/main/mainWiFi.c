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
#include "wifi.h"



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
								.data_bits = UART_DATA_8_BITS,
								.parity    = UART_PARITY_DISABLE,
								.stop_bits = UART_STOP_BITS_1,
								.flow_ctrl = UART_HW_FLOWCTRL_DISABLE
							 };

	ESP_ERROR_CHECK(uart_param_config(UART_NUM_0, &uart_cfg));
	ESP_ERROR_CHECK(uart_set_pin(UART_NUM_0, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
	ESP_ERROR_CHECK(uart_driver_install(UART_NUM_0, 4096, 0, 0, NULL, 0));

	wireshark_802_11_t raw_wifi_pkt;
	portBASE_TYPE xStatus;

	while( 1 )
	{
		xStatus = xQueueReceive(q_wifi_uart, &raw_wifi_pkt, portMAX_DELAY);
		if (xStatus == pdPASS)
		{
//			printf("len pkt = %d\n", raw_wifi_pkt.len_pkt);
//			printf("uart task\n" );
			uart_write_bytes(UART_NUM_0, (char*) raw_wifi_pkt.pkt, raw_wifi_pkt.len_pkt);
			uart_write_bytes(UART_NUM_0, "\n", 1);
		}

//		uart_write_bytes(UART_NUM_0, "*** Ready!\r\n ***", 8);
//		vTaskDelay(1000 / portTICK_PERIOD_MS);

	}
	vTaskDelete( NULL );
}



/******************************************************************************
* 						Callback function for 802.11                      	  *
*******************************************************************************/
void sniffer_wifi(void *buff, wifi_promiscuous_pkt_type_t type)
{
	wifi_promiscuous_pkt_t *capture_802_11 = (wifi_promiscuous_pkt_t *)buff;

	wireshark_802_11_t wifi_pkt;

	if ( capture_802_11->rx_ctrl.rx_state == 0)
	{
		wifi_pkt.len_pkt = (uint16_t) capture_802_11->rx_ctrl.sig_len;
		memcpy(wifi_pkt.pkt,capture_802_11->payload, capture_802_11->rx_ctrl.sig_len);
		xQueueSendFromISR(q_wifi_uart, &wifi_pkt, NULL);
	}

//	if (type == WIFI_PKT_DATA)
//	{
//		printf("%d\n", wifi_pkt.len_pkt);
//	}

//	xQueueSendFromISR(q_wifi_uart, &wifi_pkt, NULL);


//	uart_write_bytes(UART_NUM_0, (char *) &len_pkt, 2);
//	uart_write_bytes(UART_NUM_0, "\n", 1);

//	uart_write_bytes(UART_NUM_0, (char*) capture_802_11->payload, capture_802_11->rx_ctrl.sig_len);
//	uart_write_bytes(UART_NUM_0, "\n", 1);

}


/******************************************************************************
* 						Main() application                          		  *
*******************************************************************************/
void app_main()
{

	q_wifi_uart = xQueueCreate(10, sizeof(wireshark_802_11_t));

	if (q_wifi_uart != NULL)
	{
		xTaskCreate(vUartTask, "UartTask", 8192, NULL, 1, NULL);

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
		esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
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

