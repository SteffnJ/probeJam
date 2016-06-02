#!/bin/bash

# Takes in arguments and setups the WiFi adapter respectively
# Usage: ./setupAdapter.sh <interface> <channel>
if [[ $# < 1 ]]
then
    echo "Usage: ./setupAdapter.sh <interface> [channel]";
    exit;
fi

ifconfig $1 down;
iwconfig $1 mode monitor;

if [[ $# == 2 ]]
then
    iwconfig $1 channel $2;
fi

ifconfig $1 up

