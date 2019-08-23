# Caterham-OBD

This repository contains code, packet captures and other files used to analyse the communications protocols used on the OBD canbus port of modern (c 2017-2019) Catherham Sevens.

Catherhams use an ECU from MBE Systems (http://www.mbesystems.com) and the 9A4 ECU is the default ECU supplied by Caterham.

SBD Motorsport (https://www.sbdmotorsport.co.uk/index.php/) supplies a Windows application called Easimap (https://www.sbdmotorsport.co.uk/index.php/products/index/4327), which can be used to access the 9A4 ECU through a CANbus to USB interface (https://www.sbdmotorsport.co.uk/index.php/products/index/2663)

This repository provides tools to manipulate the Easimap configuration files (ec2 files) and to analyse captures of SocketCAN interactions between a monitoring application and the 9A4 ECU.
