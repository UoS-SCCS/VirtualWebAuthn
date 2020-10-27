sudo cp 70-solokeys-access.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules && udevadm trigger
