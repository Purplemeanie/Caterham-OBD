# Caterham-OBD

This repository contains code, packet captures and other files used to analyse the communications protocols used on the OBD canbus port of modern (c 2017-2019) Catherham Sevens.

Catherhams use an ECU from MBE Systems (http://www.mbesystems.com) and the 9A4 ECU is the default ECU supplied by Caterham.

SBD Motorsport (https://www.sbdmotorsport.co.uk/index.php/) supplies a Windows application called Easimap (https://www.sbdmotorsport.co.uk/index.php/products/index/4327), which can be used to access the 9A4 ECU through a CANbus to USB interface (https://www.sbdmotorsport.co.uk/index.php/products/index/2663)

This repository provides tools to manipulate the Easimap configuration files (ec2 files) and to analyse captures of SocketCAN interactions between a monitoring application and the 9A4 ECU.

The Programming Interface (API) to the code is as follows: 

mbe()

Creates an mbe class object with no parameters

set_options(vars_file, request_id, response_id, interface)

Sets the mbe options.

vars_file: A JSON encoded representation of the Easimap EC2 file. This is used to define all the variables the ECU can process. It also sets offset and scaling configurations for each of the variables. This file is created using ec2parse.py and the latest version of the JSON vars_file can be found at 9A4be52a.ec2.utf8.json.

request_id: This is the CAN bus ID needed to tell mbe.py what ID to use when making requests to the ECU. This parameter may be ignored and mbe.py will use the default 0x0cbe1101.

response_id: This is the CAN bus ID needed to tell mbe.py what ID to look for when receiving responses for the ECU. This parameter may be ignored and mbe.py will use the default 0x0cbe0111.

interface: defaults to can0

RETURN: Returns False is there was a problem setting these options

add_variable_list(list)

Adds a list of variables to the mbe class to be processed later.

list: an array of strings defining which ECU variables to request and process with process_all_pages()

RETURN: False if there is problem with the list, otherwise returns True

bind()

Opens and binds mbe.py to can-isotp kernel module.

RETURN: True

process_all_pages(results)

Processes all variables.

results: A dictionary indexed by the variable name string and supplying results, units, and human readable string for each variable.

RETURN: a dictionary of results, otherwise returns False if there's a problem.
