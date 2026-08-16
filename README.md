# ESPSlopkit
ESP32 Slopkit is built from VS Code with PlatformIO.
It has tested on ESP32-S3FN8 dongle with PS5 firmware 10.01

![image](https://github.com/MacleodTW/ESPSlopkit/blob/main/ESP32%20S3%20Dongle.png)


Usage:
01. Download release ESPSlopkit_xxx.zip
02. Flash ESP32-S3 dongle with the tool inside zip
03. Plug ESP32-S3 dongle to recycle power
04. Phone or PC WiFi connect to "PS_WiFi" SSID, password is "password"
05. Use browser to https://10.1.1.1 (Contiue insecure)
06. Set STA WiFi SSID and STA WiFi password then click "Save"
07. Reload browser get STA IP
08. PS5 set DNS server to STA IP
09. PS5 Settings -> Guide & Tips, Health and Safety, and Other information -> User's Guide -> If it shows security xxx click "Yes"
10. Click jailbreak. After all is done, it shows "Payload Manager" and "Webkit Autoloader Installer" buttons to send payload

Credit:<BR>
jordyidk - <a href="https://github.com/jordyidk/slopkit">slopkit</a><BR>
itsPLK - <a href="https://github.com/itsPLK/ps5-payload-manager">ps5-payload-manager</a><BR>
itsPLK - <a href="https://github.com/itsPLK/ps5-webkit-autoloader/">ps5-webkit-autoloader</a><BR>
