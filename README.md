# NSCOM03-Network-Sniffer
_A Network Sniffing Tool created for Data Communications (NSCOM03)_\
Date Accomplished: February 13, 2021

## Use
This project sniffs for packets within the network.

## Pre-requisites
1. Python / Python3
  * Programming language used.
  * To download in **Linux**: `sudo apt-get install python3`
  * To download in **Windows**: [Python for Windows](https://www.python.org/downloads/windows/)
2. Curl
  * Command that allows the transfer (upload / download) of data using command line interface.
  * To download in **Linux**: `sudo apt-get install curl`
  * To download in **Windows**: [Curl for Windows](https://curl.se/windows/)

## Download
Download the project through the following commands:
* Linux:
``` sudo curl -O https://raw.githubusercontent.com/bernicebetito/NSCOM03-Network-Sniffer/main/network_sniffer.py ```
* Windows:
``` curl -O https://raw.githubusercontent.com/bernicebetito/NSCOM03-Network-Sniffer/main/network_sniffer.py ```

Once downloaded, the project can be used through the following commands:
* Linux: ` sudo python3 network_sniffer.py `
* Windows: ` python network_sniffer.py `

## Guide
Upon running the project, sniffing of packets will automatically start. To stop sniffing for packets, enter `CTRL + C`. Once packet sniffing is stopped, Total Number of Packets, Time, IP Address Mapping, Protocol Statistics, and Top 5 Conversations would be shown in the console and in the txt file created.
