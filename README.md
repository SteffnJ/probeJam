# probeJam
Woopwoopwoop, finally a program that lets you log probe requests and probe responses. Additionally, this program has a targeted jam functionality, meaning you don't have to jam everyone on the network in order to jam your target.


### Version
0.1


## Introduction
Partly educational, partly lulz, partly because I haven't found a software that does exactly what I want. Lately, my interest has grown for lower level network programming. I was informed of Scapy and it is just fantastic! The last half a year, I've gotten more into digital privacy and some social engineering. After hearing about probe requests, I started reading more about it and wanted to write some software that logs this as this is potentially sensitive and private information - and it creates a wider attack surface (read jamming).


## Installation
Dependencies:
*Python2.7
*Scapy
*WiFi adapter that supports monitor mode*

\*If you want to use the `setupAdapter.sh` script, you would need iwconfig and ifconfig installed as well.

In order to use probeJam.py it is crucial that your wireless card is in monitor mode and you use this interface as a parameter to probeJam.py. Chances are you will have to run this as root user under most circumstances. I take no responsibility for whatever.


## Usage
It can't be used. Just kidding. Type in `--help` as a parameter and off you go. Really though, monitor mode before you start probeJam.py.

For now, probeJam can be used in either a jamming mode (passing in `-j` and respective arguments, check `--help`!) or as a probe request/response logger. You can also use `-l` and pass in a logFile that the probe requests/responses will be logged to. Be careful about this file as you will run this as root.

Personally, I am using this program on a Kali 64-bit VM through VirtualBox - I am also using an external WiFI adapter that is passed through the host system and is 'native' to the VM.


## Visions for the future
*Give in an SSID and jam everyone that has been connected to the SSID (based on probe requests)
*Implement a feature that jams a target before sniffing up all the SSIDs
*Other?

## Licence
MIT License

Copyright (c) 2016 Steffen 'SteffnJ' Johansen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
