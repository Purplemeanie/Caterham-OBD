# mbepcap2txt
# Takes an pcap with ISOTP formatted MBE transactions and makes it human readable. 
#
# 2019-08-20 John Martin
#

''' Here's some useful commands for python
import pyshark
packets = pyshark.FileCapture('Easimap talking to Caterham only ISOTP frames.pcapng', decode_as={'can.subdissector':'iso15765'})
pkt0 = packets[0]
>>> pkt0.layers
[<SLL Layer>, <CAN Layer>, <ISO15765 Layer>, <DATA Layer>]

And a useful tshark command...
tshark -r Easimap\ talking\ to\ Caterham\ only\ ISOTP\ frames.pcapng -Y '(frame.number == 3)' -T pdml -d can.subdissector=iso15765

'''

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
    #    print(v['name'])
    return variables

def create_page_reverse_mapping(variables):
    mapping = dict();
    for i in variables:
        LSBstring = variables[i]['address'][-2:]
        try:
          temp = mapping[variables[i]['page']]
        except:
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
    print(f"This is a command request for data in page: {page} ...")
    # Iterate through the remaining message and lookup the number of bytes to extract in the response
    i = 12
    while(i < data_length):
        byte = data[i:i+2]
        #print(f"{byte} ")
        try:
            mapped = mapping["0x"+page][byte]
        except:
            mapped = {'name':"UNKNOWN", 'bytes':"1"}
        bytes = mapped['bytes']
        variable = mapped['name']
        #pprint.pprint(mapped)
        command_structure.append(mapped);
        i = i + (int(bytes) * 2)
    pprint.pprint(command_structure)
    return command_structure

def process_data_response(data, request_command, variables):
    #81aaaa1600
    data_length = len(data)
    if (data_length < 4):
        return None
    i = 2
    response_count = 1
    print(f"This is a command response for data...")
    for command in request_command:
        print(f"\nResponse: {response_count}")
        
        variable = None

        response_data = ""
        if (command['name'] != "UNKNOWN"):
            print(f"This is the variable info for {command['name']}")
            variable = variables[command['name']]
            pprint.pprint(variable)
            bytes = int(command['bytes'])
            for y in range (0,bytes):
                byte = data[i+(y*2):(i+(y*2))+2]
                response_data = str(byte) + str(response_data)
        else:
            print(f"There is no EC2 variable for {command['name']}")
            bytes = int(command['bytes'])
            for y in range (0,bytes):
                byte = data[i+(y*2):(i+(y*2))+2]
                response_data = str(byte) + str(response_data) # This is the right byte orientation
        
        i = i + (bytes*2)
        response_count = response_count + 1
        
        additional_string = ""
        if(variable != None):
          scale = float(variable['scale_maximum']) - float(variable['scale_minimum'])
          dividend = (2 ** (int(variable['bytes']) * 8)) - 1
          response_int = int(response_data,16)
          response_scaled = ((float(response_int * scale)) / float(dividend)) + float(variable['scale_minimum'])
          offset = float(variable['scale_minimum'])
          print(f"{command['name']}={response_scaled:.5} {variable['units']} ({variable['short_desc']} ) [0x{response_data}={int('0x'+response_data, 16)}, Scale:{scale}, Div:{dividend}, Offset:{offset:.3}]")
        else:
          print(f"{command['name']}: 0x{response_data}, {int('0x'+response_data, 16)}")
    return None

def main():
    # Setup and parse command line args
    parser = argparse.ArgumentParser(prog='mbepcap2txt', description='Takes an pcap with ISOTP formatted MBE transactions and makes it human readable.')
    parser.add_argument('--input',         '-i',                   help='Input pcap filename', required=True)
    parser.add_argument('--variables',     '-v',                   help='Input MBE variables filename', required=True)
    parser.add_argument('--query_id',      '-q',                   help='CAN query ID (default 0x0cbe1101)', default=0x0cbe1101)
    parser.add_argument('--response_id',   '-r',                   help='CAN resdponse ID (default 0x0cbe0111', default=0x0cbe0111)
    parser.add_argument('--version',       '-V', action='version', version='%(prog)s '+version)
    
    args = parser.parse_args()
    
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
          has_isotop = False
          
      if (not ((has_can) and (has_isotp))):
            print("Bummer, not a can/iso15765 packet")
            pprint.pprint(pkt.layers)
            continue

      can_id = pkt.can.id
      
      if(can_id != args.query_id and can_id != args.response_id):
      	  print("This isn't a packet we're interested in")
      	  continue
      
      data = pkt.data.data
      # Message Types: 0x00=Single Frame, 0x01=First Frame, 0x02=Consecutive Frame
      message_type = int(pkt.iso15765.message_type[2:])
      try:
        fragment_count = pkt.iso15765.fragment_count
      except:
        fragment_count = None
            
      print(f"### PCAP Packet {i+1} #### CAN ID={can_id}, data={data}, ISOTP Message Type={message_type}, ISOTP Fragment Count={fragment_count}")

      if (can_id == args.query_id):
            # If its a single frame then process it, otherwise wait for the final frame that has fragment_count set
            if(message_type == 0x00 or fragment_count != None):
                  command = data[:2]
                  if(command == "01"): # A data request
                      pending_data_request_command = process_data_request_command(data, mappings)
                  elif(command == "04"):
                      print("This is a config request")
      elif (can_id == args.response_id):
            # If its a single frame then process it, otherwise wait for the final frame that has fragment_count set
            if(message_type == 0x00 or fragment_count != None):
                  command = data[:2]
                  if(command == "81"): # A data response
                      process_data_response(data, pending_data_request_command, variables)
                  elif(command == "e4"):
                      print("This is a config response")
    
    cap.close()
    

if __name__ == '__main__':
    main()