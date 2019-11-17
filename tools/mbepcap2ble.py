# mbepcap2txt
# Takes an pcap with ISOTP formatted MBE transactions and pumps it over a nordic UART BLE connection.
#
# 2019-08-20 John Martin
#

# Here's some useful commands for python
# import pyshark
# packets = pyshark.FileCapture('Easimap talking to Caterham only ISOTP frames.pcapng', decode_as={'can.subdissector':'iso15765'})
# pkt0 = packets[0]
# >>> pkt0.layers
# [<SLL Layer>, <CAN Layer>, <ISO15765 Layer>, <DATA Layer>]
# 
# And a useful tshark command...
# tshark -r Easimap\ talking\ to\ Caterham\ only\ ISOTP\ frames.pcapng -Y '(frame.number == 3)' -T pdml -d can.subdissector=iso15765
# 
# Example command line:
# python3 mbepcap2txt.py -i ../captures/Easimap-Engine-Start-and-Running-001-ISO-only.pcapng -v ../ec2/9A4be52a.ec2.utf8.json -q 0x0cbe1101 -r 0x0cbe0111
#

import logging
import argparse
import re
import csv
import json
import pprint
import pyshark
import binascii

version = "0.1"

def load_mbe_variables(filename):
	f = open(filename, "r")
	variables = dict()
	variables = json.load(f)
	#for v in variables:
	#    logging.debug(v['name'])
	return variables

def create_page_reverse_mapping(variables):
	mapping = dict()
	for i in variables:
		LSBstring = variables[i]['address'][-2:]
		if(not variables[i]['page'] in mapping):
			mapping[variables[i]['page']] = dict()
		mapping[variables[i]['page']][LSBstring] = variables[i]['bytes']
		# Possibly don't need to store bytes as well as name... could get it from the main variables list, but what the heck
		mapping[variables[i]['page']][LSBstring] = {'name':variables[i]['name'], 'bytes':variables[i]['bytes']}
	#pprint.pprint(mapping)
	return mapping

def process_data_request_command(data, mapping):
	# Build a format array
	# 0100000000126667a8a9
	command_structure = list()
	data_length = len(data)
	if (data_length < 12):
		return None
	# Get the page number
	page = data[10:12]
	logging.debug(f"This is a command request for data in page: {page} ...")
	# Iterate through the remaining message and lookup the number of bytes to extract in the response
	i = 12
	while(i < data_length):
		byte = data[i:i+2]
		#logging.debug(f"{byte} ")
		try:
			mapped = mapping["0x"+page][byte]
		except:
			mapped = {'name':"UNKNOWN", 'bytes':"1"}
		bytes = mapped['bytes']
		#pprint.pprint(mapped)
		command_structure.append(mapped)
		i = i + (int(bytes) * 2)
	logging.debug(pprint.pformat(command_structure))
	return command_structure

def process_data_response(data, request_command, variables):
	#81aaaa1600
	data_length = len(data)
	if (data_length < 4):
		return None
	i = 2
	response_count = 1
	logging.debug(f"This is a command response for data...")
	for command in request_command:
		logging.debug(f"\nResponse: {response_count}")

		variable = None

		response_data = ""
		if (command['name'] != "UNKNOWN"):
			logging.debug(f"This is the variable info for {command['name']}")
			variable = variables[command['name']]
			logging.debug(pprint.pformat(variable))
			bytes = int(command['bytes'])
			for y in range (0,bytes):
				byte = data[i+(y*2):(i+(y*2))+2]
				response_data = str(byte) + str(response_data)
		else:
			logging.debug(f"There is no EC2 variable for {command['name']}")
			bytes = int(command['bytes'])
			for y in range (0,bytes):
				byte = data[i+(y*2):(i+(y*2))+2]
				response_data = str(byte) + str(response_data) # This is the right byte orientation

		i = i + (bytes*2)
		response_count = response_count + 1

		if(variable != None):
			scale = float(variable['scale_maximum']) - float(variable['scale_minimum'])
			dividend = (2 ** (int(variable['bytes']) * 8)) - 1
			response_int = int(response_data,16)
			response_scaled = ((float(response_int * scale)) / float(dividend)) + float(variable['scale_minimum'])
			offset = float(variable['scale_minimum'])
			print(f"{command['name']}={response_scaled:.5} {variable['units']} ({variable['short_desc']} ) [0x{response_data}={int('0x'+response_data, 16)}, Scale:{scale}, Div:{dividend}, Offset:{offset:4}]")
		else:
			print(f"{command['name']}: 0x{response_data}, {int('0x'+response_data, 16)}")
	return None

def main():
	# Setup and parse command line args
	parser = argparse.ArgumentParser(prog='mbepcap2txt', description='Takes an pcap with ISOTP formatted MBE transactions and makes it human readable.')
	parser.add_argument('--input',         '-i',                   help='Input pcap filename', required=True)
	parser.add_argument('--can',           '-c',                   help='Display raw can data', action='store_true', default=False)
	parser.add_argument('--isotp',         '-I',                   help='Display raw isotp data', action='store_true', default=False)
	parser.add_argument('--mbe',           '-m',                   help='DON\'T Display mbe decoded data', action='store_false', default=True)
	parser.add_argument('--variables',     '-v',                   help='Input MBE variables filename', required=True)
	parser.add_argument('--query_id',      '-q',                   help='CAN query ID (default 0x0cbe1101)', default='0x0cbe1101')
	parser.add_argument('--response_id',   '-r',                   help='CAN resdponse ID (default 0x0cbe0111)', default='0x0cbe0111')
	parser.add_argument('--loglevel',      '-l',                   help='Logging level to show', choices=['INFO','DEBUG','WARNING', 'ERROR', 'NONE'], default="INFO")
	parser.add_argument('--logfile',       '-f',                   help='If set logging will be sent to this file')
	parser.add_argument('--version',       '-V', action='version', version='%(prog)s '+version)

	args = parser.parse_args()

	logging_level = getattr(logging, args.loglevel, None)
	logging.basicConfig(level=logging_level, filename=args.logfile, filemode='w')

	if args.input == None:
		parser.print_help()
		exit()

	variables = load_mbe_variables(args.variables)
	mappings = create_page_reverse_mapping(variables)

	cap = pyshark.FileCapture(args.input, decode_as={'can.subdissector':'iso15765'}, keep_packets=False)

	i = 0

	for pkt in cap:
		i = i + 1
		#Need to check we have a packet with CAN and ISOTP layers
		try:
			if(pkt.can != None): has_can = True
		except:
		  has_can = False
		try:
			if(pkt.iso15765 != None): has_isotp = True
		except:
			has_isotp = False

		if (not ((has_can) and (has_isotp))):
			logging.debug("Bummer, not a can/iso15765 packet")
			logging.debug(pprint.pformat(pkt.layers))
			continue

		can_id = pkt.can.id

		if(can_id != args.query_id and can_id != args.response_id):
	  		logging.debug("This isn't a packet we're interested in")
	  		continue

		data = pkt.data.data
		# Message Types: 0x00=Single Frame, 0x01=First Frame, 0x02=Consecutive Frame
		message_type = int(pkt.iso15765.message_type[2:])
		try:
			fragment_count = int(pkt.iso15765.fragment_count)
		except:
			fragment_count = 0

		output_log_line = False
		if (args.can):
			can_string = f"CAN ID={can_id}"
			output_log_line = True
			output_data = data
		else:
			can_string = ""

		command_string = ""
		if(args.isotp and (message_type == 0x00 or fragment_count > 0)):
			command = data[:2]
			if (can_id == args.query_id):
				if (command == "01"):
					command_string = "REQUEST "
				elif (command == '04'):
					command_string = "OTHER_REQUEST"
				else:
					command_string = "UNKNOWN_MBE_MESSAGE"
			elif (can_id == args.response_id):
				if (command == '81'):
					command_string = "RESPONSE"
				elif (command == 'e4'):
					command_string = "OTHER_RESPONSE"
				else:
					command_string = "UNKNOWN_MBE_MESSAGE"
			isotp_string = f"ISOTP MBE Type={message_type}, Fragments={fragment_count}, {command_string} "
			output_data = data
			output_log_line = True
		else:
			isotp_string = ""
		
		if (output_log_line):
			print(f"#[{i+1}]# {can_string}{isotp_string}:{output_data}")

		if (args.mbe):
			if (can_id == args.query_id):
				# If its a single frame then process it, otherwise wait for the final frame that has fragment_count set
				if(message_type == 0x00 or fragment_count > 0):
					command = data[:2]
					if(command == "01"): # A data request
						pending_data_request_command = process_data_request_command(data, mappings)
					elif(command == "04"):
						logging.debug("This is a config request")
			elif (can_id == args.response_id):
				# If its a single frame then process it, otherwise wait for the final frame that has fragment_count set
				if(message_type == 0x00 or fragment_count > 0):
					command = data[:2]
					if(command == "81"): # A data response
						process_data_response(data, pending_data_request_command, variables)
					elif(command == "e4"):
						logging.debug("This is a config response")

	cap.close()


if __name__ == '__main__':
	main()

'''
# Example of interaction with a BLE UART device using a UART service
# implementation.
# Author: Tony DiCola
import Adafruit_BluefruitLE
from Adafruit_BluefruitLE.services import UART
import time
import json


# Get the BLE provider for the current platform.
ble = Adafruit_BluefruitLE.get_provider()


# Main function implements the program logic so it can run in a background
# thread.  Most platforms require the main thread to handle GUI events and other
# asyncronous events like BLE actions.  All of the threading logic is taken care
# of automatically though and you just need to provide a main function that uses
# the BLE provider.
def main():
    # Clear any cached data because both bluez and CoreBluetooth have issues with
    # caching data and it going stale.
    ble.clear_cached_data()

    # Get the first available BLE network adapter and make sure it's powered on.
    adapter = ble.get_default_adapter()
    if (not adapter.is_powered):
        adapter.power_on()
        print('Using adapter: {0}'.format(adapter.name))
        time.sleep(2.0)
    else:
        print(f'Adapter {adapter.name} already powered on')

    # Disconnect any currently connected UART devices.  Good for cleaning up and
    # starting from a fresh state.
    print('Disconnecting any connected UART devices...')
    UART.disconnect_devices()

    # Scan for UART devices.
    print('Searching for UART device...')
    try:
        adapter.start_scan()
        # Search for the first UART device found (will time out after 60 seconds
        # but you can specify an optional timeout_sec parameter to change it).
        device = UART.find_device()
        if device is None:
            raise RuntimeError('Failed to find UART device!')
    finally:
        # Make sure scanning is stopped before exiting.
        adapter.stop_scan()

    time.sleep(2.0)
    print(f'Connecting to device... {device.name}')
    device.connect()  # Will time out after 60 seconds, specify timeout_sec parameter
                      # to change the timeout.

    # Once connected do everything else in a try/finally to make sure the device
    # is disconnected when done.
    try:
        # Wait for service discovery to complete for the UART service.  Will
        # time out after 60 seconds (specify timeout_sec parameter to override).
        print('Discovering services...')
        UART.discover(device)

        # Once service discovery is complete create an instance of the service
        # and start interacting with it.
        uart = UART(device)

        count = 1
        while(True):
            # Write a string to the TX characteristic.
            #uart.write('Hello world!\r\n')
            bytesToWrite = bytearray()
            #bytesToWrite.extend(map(ord, f'Hello World!...Hello World!...Hello World!...Hello World!...Hello World!... {count}\r\n'))
            jsonString = json.dumps({'command': "ping", "count": f"{count}"})
            bytesToWrite.extend(map(ord, jsonString + "\n"))
            uart.write(bytesToWrite)
            print(f"Sent 'Hello world!' {count} times to the device.")
            count += 1

            # Now wait up to one minute to receive data from the device.
            print('Waiting receive data from the device...')
            received = uart.read(timeout_sec=10)
            if received is not None:
                # Received data, print it out.
                print('Received: {0}'.format(received))
            else:
                # Timeout waiting for data, None is returned.
                print('Received no data!')
    finally:
        # Make sure device is disconnected on exit.
        print(f"Disconnecting device {device.name}")
        device.disconnect()


# Initialize the BLE system.  MUST be called before other BLE calls!
ble.initialize()

# Start the mainloop to process BLE events, and run the provided function in
# a background thread.  When the provided main function stops running, returns
# an integer status code, or throws an error the program will exit.
ble.run_mainloop_with(main)
'''
