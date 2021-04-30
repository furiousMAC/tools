#!/bin/bash

## Script to collect BLE PCAP using nRF52840 on Linux or macOS systems
## Note: nRF Sniffer (https://infocenter.nordicsemi.com/index.jsp?topic=%2Fug_sniffer_ble%2FUG%2Fsniffer_ble%2Finstalling_sniffer.html) is required

if [[ $EUID -ne 0 ]]; then
	echo "[+] This script must be run as root"
	exit 1
fi

os=$(uname)
filename=$(date -u +%Y%m%d-%H%M%SZ)-ble.pcapng

if [ "$os" == "Darwin" ]; then
        echo '[+] macOS OS detected'
	dev="/dev/cu.usbmodem*"
elif [ "$os" == "Linux" ]; then
        echo '[+] Linux OS detected'
	dev="/dev/ttyACM0"
fi

wireshark -k -w $filename -i $dev
editcap -F pcapng $filename - | gzip > "${filename%%.*}".pcapng.gz && rm $filename
