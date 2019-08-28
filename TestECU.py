# TestECU
# Application for testing python-isotp-mbe class
#
# 2019-08-26 John Martin
#

import logging
import argparse
import re
import csv
import json
import pprint
import pyshark
import binascii
from mbe import mbe
import curses

version = "0.1"

variables_to_follow = [
#    'RT_THROTTLESITE1',
#    'RT_BATTERYVOLTAGECOMP',
#    'RT_IGNITIONADVANCEBANK1',
#    'RT_TPSVSSPEEDIGN+TRIM1',
#    'RT_INJECTIONTIMEA',
    'RT_COOLANTTEMP1(LIM)',
    'RT_AIRTEMP1(LIM)',
#    'RT_MAPPINGPOT1LIM',
#    'RT_MAPPINGPOT2LIM',
#    'RT_COOLANTFUELFACTOR',
    'RT_BATTERYVOLTAGE(LIM)',
#    'RT_AIRTEMPFUELFACTOR',
#    'RT_DUTYCYCLEA',
#    'RT_TPSFUEL+TRIMBANK1',
    'RT_SOFTCUTTIME',
    'RT_HARDCUTTIME',
#    'RT_THROTTLEANGLE1(RAW)',
#    'RT_ENGINERUNTIME',
##    'RT_ECUSTATUS',
#    'RT_BAROSCALEDLIM',
#    'RT_THROTTLEANGLEINCREASING',
#    'RT_BAROFUELCOMP',
#    'RT_CRANKCOUNT',
	'RT_ENGINESPEED'
]

def main():
	parser = argparse.ArgumentParser(prog='mbepcap2txt', description='Takes an pcap with ISOTP formatted MBE transactions and makes it human readable.')
	parser.add_argument('--interface',     '-i',                   help='The can interface to open', required=True)
	parser.add_argument('--variables',     '-v',                   help='Input MBE variables filename', required=True)
	parser.add_argument('--query_id',      '-q',                   help='CAN query ID (default 0x0cbe1101)', default=0x0cbe1101)
	parser.add_argument('--response_id',   '-r',                   help='CAN resdponse ID (default 0x0cbe0111', default=0x0cbe0111)
	parser.add_argument('--loglevel',      '-l',                   help='Logging level to show', choices=['INFO','DEBUG','WARNING', 'ERROR', 'NONE'], default="ERROR")
	parser.add_argument('--logfile',       '-f',                   help='If set logging will be sent to this file')
	parser.add_argument('--version',       '-V', action='version', version='%(prog)s '+version)

	args = parser.parse_args()

	logging_level = getattr(logging, args.loglevel, None)
	logging.basicConfig(level=logging_level, filename=args.logfile, filemode='w')

	ecu = mbe()
	
	mbe.set_options(args.variables, args.query_id, args.response_id, args.interface)

	#ecu.log_variables(2)
	#ecu.log_pages(2)

	if(ecu.add_variable_list_to_follow(variables_to_follow) != len(variables_to_follow)):
		logging.warning("Ooops, didn't add all the vars I wanted to")
	else:
		logging.info("Added all the variables we expected")

	ecu.bind()

	results = dict()
	if (ecu.process_all_pages(results) != False):
		logging.debug(pprint.pformat(results))

if __name__ == '__main__':
	main()
