import serial

DEFAULT_TTY_ESP32 = '/dev/ttyUSB0'
# DEFAULT_TTY_ESP32_BAUDRATE = 115200
DEFAULT_TTY_ESP32_BAUDRATE = 921600

ser = serial.Serial(DEFAULT_TTY_ESP32, baudrate=DEFAULT_TTY_ESP32_BAUDRATE)
# ser.write(b'helloqwert\n')
ser.write(b'\x01\x01\x00')
ser.close()

