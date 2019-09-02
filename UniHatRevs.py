# TestECU
# Application for testing python-isotp-mbe class
#
# 2019-08-26 John Martin
#

import logging
import argparse
import csv
import json
import pprint
import binascii
import mbe
import unicornhat as uh
import math
import time

version = "0.1"
rev_limit = 4000

uh.set_layout(uh.AUTO)
uh.rotation(0) # tested on pHAT/HAT with rotation 0, 90, 180 & 270
uh.brightness(0.5)
u_width,u_height=uh.get_shape()

if (mbe.test_mode):
	variables_to_follow = [
	    'RT_ENGINESPEED',
		'RT_AIRTEMP1(LIM)',
		'RT_COOLANTTEMP1(LIM)',
		'RT_BATTERYVOLTAGE(LIM)',
		'RT_SOFTCUTTIME',
		'RT_HARDCUTTIME'
	]
else:
	variables_to_follow = [
#    	'RT_THROTTLESITE1',
#    	'RT_BATTERYVOLTAGECOMP',
#    	'RT_IGNITIONADVANCEBANK1',
#    	'RT_TPSVSSPEEDIGN+TRIM1',
#    	'RT_INJECTIONTIMEA',
#    	'RT_COOLANTTEMP1(LIM)',
    	'RT_AIRTEMP1(LIM)',
#    	'RT_MAPPINGPOT1LIM',
#    	'RT_MAPPINGPOT2LIM',
#    	'RT_COOLANTFUELFACTOR',
    	'RT_BATTERYVOLTAGE(LIM)',
#    	'RT_AIRTEMPFUELFACTOR',
#    	'RT_DUTYCYCLEA',
#    	'RT_TPSFUEL+TRIMBANK1',
    	'RT_SOFTCUTTIME',
    	'RT_HARDCUTTIME',
#    	'RT_THROTTLEANGLE1(RAW)',
#    	'RT_ENGINERUNTIME',
##   	 'RT_ECUSTATUS',
#    	'RT_BAROSCALEDLIM',
#    	'RT_THROTTLEANGLEINCREASING',
#    	'RT_BAROFUELCOMP',
#    	'RT_CRANKCOUNT',
		'RT_ENGINESPEED'
	]

# Display a graph, and as it grows it turns from green to yellow to red
def unicorn_revs(revs):
	to_paint = min(u_width - 1,int(math.ceil((float(u_width - 1) * float(revs)) / float(rev_limit)))) # Need a number between 0 and 7
	#uh.clear()

	if (to_paint >= 7):
		r,g,b = 0x80, 0x00, 0x00  # Red
	elif (to_paint >=4 ):
		r,g,b = 0xff, 0xff, 0x00  # Yellow
	else:
		r,g,b = 0x00, 0xff, 0x00  # Green

	# Iterate over the whole array, that way we don't have to issue clear() and hopefully won't get flickering
	for row in range(0, u_height):
		for col in range (0, u_width):
			if ((row <= to_paint) and (col <= to_paint)): # Only paint the bits we want in colour
				uh.set_pixel(row,col,r,g,b)
			else:
				uh.set_pixel(row,col,0,0,0) # Paint the bits we don't want blank
	uh.show()

def main():
	parser = argparse.ArgumentParser(prog='UniHatRevs', description='Shows rev scale on a Raspberry Pi Unicorn Hat from Pimoroni.')
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

	ecu = mbe.mbe()
	
	ret = ecu.set_options(args.variables, args.query_id, args.response_id, args.interface)
	if(not ret):
		logging.error("Unable to set options")
		exit()

	#ecu.log_variables(2)
	#ecu.log_pages(2)

	if(ecu.add_variable_list_to_follow(variables_to_follow) != len(variables_to_follow)):
		logging.warning("Ooops, didn't add all the vars I wanted to")
	else:
		logging.info("Added all the variables we expected")

	ecu.bind()

	results = dict()
	while True:
		if (ecu.process_all_pages(results) != False):
			logging.debug(pprint.pformat(results))
			unicorn_revs(results['RT_ENGINE_SPEED'])
		
		time.sleep(0.25)

if __name__ == '__main__':
	main()
