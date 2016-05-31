#!/bin/bash

ifconfig wlan0 down
iwconfig wlan0 mode monitor
iwconfig wlan0 channel 13
ifconfig wlan0 up

