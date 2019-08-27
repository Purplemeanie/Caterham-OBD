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
#    'RT_COOLANTTEMP1(LIM)',
#    'RT_AIRTEMP1(LIM)',
#    'RT_MAPPINGPOT1LIM',
#    'RT_MAPPINGPOT2LIM',
#    'RT_COOLANTFUELFACTOR',
#    'RT_BATTERYVOLTAGE(LIM)',
#    'RT_AIRTEMPFUELFACTOR',
#    'RT_DUTYCYCLEA',
#    'RT_TPSFUEL+TRIMBANK1',
#    'RT_SOFTCUTTIME',
#    'RT_HARDCUTTIME',
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
	parser.add_argument('--query_id',      '-q',                   help='CAN query ID (default 0x0cbe1101)', default='0x0cbe1101')
	parser.add_argument('--response_id',   '-r',                   help='CAN resdponse ID (default 0x0cbe0111', default='0x0cbe0111')
	parser.add_argument('--loglevel',      '-l',                   help='Logging level to show', choices=['INFO','DEBUG','WARNING', 'ERROR', 'NONE'], default="ERROR")
	parser.add_argument('--logfile',       '-f',                   help='If set logging will be sent to this file')
	parser.add_argument('--version',       '-V', action='version', version='%(prog)s '+version)

	args = parser.parse_args()

	logging_level = getattr(logging, args.loglevel, None)
	logging.basicConfig(level=logging_level, filename=args.logfile, filemode='w')

	ecu = mbe(args.variables, args.query_id, args.response_id, args.interface)

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

	# stdscr = curses.initscr()
	# # set screen attributes
	# stdscr.nodelay(1) # this is used to make input calls non-blocking
	# curses.cbreak()
	# stdscr.keypad(1)
	# curses.curs_set(0)     # no annoying mouse cursor

	# rows, cols = stdscr.getmaxyx()
	# logging.debug(f"{rows}, {cols}")

	# curses.start_color()
	# curses.noecho()

	# # create color pair's 1 and 2
	# curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_WHITE)
	# curses.init_pair(2, curses.COLOR_CYAN, curses.COLOR_BLACK)
	# curses.init_pair(3, curses.COLOR_BLACK, curses.COLOR_CYAN)

	# window = curses.newwin(rows-1, cols-1,1, 1)
	# window.clear()
	# window.box()
	# window.addstr(2, 2, "Testing")
	# window.addstr(3, 2, f"{pprint.pformat(results)}")

	# #window.noutrefresh()
	# #curses.doupdate()
	# window.refresh()

	# c = ''
	# while(c != ord('q')):
	# 	c = stdscr.getch()

	# curses.nocbreak()
	# stdscr.keypad(0)
	# curses.echo()
	# curses.endwin()

if __name__ == '__main__':
	main()
