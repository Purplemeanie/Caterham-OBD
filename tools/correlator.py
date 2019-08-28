'''
2019-09-12 Takes a CanBus wireshark .csv export and bitwise looks for a DWORD in it
'''

import argparse
import sys
import time
import csv

# Setup and parse command line args
parser = argparse.ArgumentParser(prog='correlator', description='Takes a CanBus wireshark .csv export and bitwise looks for a DWORD in it')
parser.add_argument('--file',          '-f',                   help='Input filename')
parser.add_argument('--dword',         '-d',                   help='DWORD to look for', )
parser.add_argument('--id',            '-i',                   help='Only search in messages with this ID (not implemented)')
parser.add_argument('--version',       '-V', action='version', version='%(prog)s 0.1')

args = parser.parse_args()

if args.file == None or args.dword == None:
	parser.print_help()
	exit()

try:
	dword_int = int(args.dword, 16)
except ValueError:
	#Handle the exception
	print('Please enter an 16bit hex integer for dword')
	parser.print_help()
	exit()

print("Using file: ", args.file)
print("Bitwise search for: ", hex(dword_int))

with open(args.file) as csvfile:
    readCSV = csv.DictReader(csvfile, delimiter=',')
    for row in readCSV:
        data = row['Info'].split(" ")

        if data[0] == "XTD:":
       		hex_data_as_string = "0x"+data[4]+data[5]+data[6]+data[7]+data[8]+data[9]+data[10]+data[11]
       		data_integer = int(hex_data_as_string,16)

        	print(f"Row {row['No.']}, Data:0x({data_integer:016x}), 0b({data_integer:064b})")

        	for x in range(48,-1,-1):
        		shifted_data = data_integer >> x
        		if (shifted_data & 0xffff) == dword_int:
        			print("Found something: ")
        			print(f"Row/Bit: {row['No.']}/{x}, DW: 0x({dword_int:04x}), DW: 0b({dword_int:016b}), Data: 0x({data_integer:016x}), Data: 0b({data_integer:064b}), SHIFTED: {shifted_data & 0xffff:04x}")
        			exit()
