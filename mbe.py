# python-isotp-mbe
# Class for handling interactions with MBE 9A4 ECU on top of ISOTP and CAN
#
# 2019-08-26 John Martin
#

''' Some sample data of a car running '''
sample_data = [
  {'request':'0100000000f83031363744454c4d4e4f50515a5b5c5d646a6b7c7d9e9fa0a1d8d9dadb', 'response':'81bc5c9d45fe548a4e7085bc5c7417f2799eb04fc409e8af8e0500800080'},
  {'request':'0100000000f9babbbcbd',                                                   'response':'81781edc1e'},
  {'request':'0100000000fa64656c',                                                     'response':'81482458'},
  {'request':'0100000000fd202425264042434d',                                           'response':'81a900000180b00040'},
  {'request':'0100000000126667a8a9',                                                   'response':'81746b1600'},
  {'request':'01000000001a525c5d',                                                     'response':'81846e12'},
  {'request':'0100000000e2cccdcecf',                                                   'response':'81ffffff07'}
]

import logging
import json
import re
import binascii
import itertools
import pprint
#import isotp

version = "0.1"

#log = logging.getLogger( 'python-mbe' )
#logging.setLevel( logging.DEBUG )

class mbe():
    # Initialize class using a filename to load json ec2 definitions and tx(query) and rx(response) CAN id's
    def __init__(self, filename, txid=None, rxid=None, interface="can0"):
        logging.debug("Init")
        self.ecu_variables = self.load_mbe_variables_from_json(filename)
        self.ecu_mappings = self.create_page_reverse_mapping(self.ecu_variables)
        self.ecu_vars_to_follow = dict()
        self.interface = interface
        logging.debug("End of Init")

    # Load the json ec2 definitions
    def load_mbe_variables_from_json(self, filename):
        f = open(filename, "r")
        logging.info(f)
        if( f == None):
            logging.debug(f"Unable to load {filename}")
            exit()
        variables = dict()
        variables = json.load(f)
        return variables

    # Debug routine to make sure we've got some good variables loaded
    def log_variables(self, count=None):
        i = 0
        for var in self.ecu_variables.values():
            logging.info(pprint.pformat(var))
            i = i + 1
            if((count != None) and (i > count)):
                break

    # Create a reverse mapping dictionary of the pages/LSBs we've loaded, the length of each var (bytes) and names
    def create_page_reverse_mapping(self, variables):
        mapping = dict()
        for i in variables:
            LSBstring = variables[i]['address'][-2:]
            try:
                temp = mapping[variables[i]['page']]
            except:
                mapping[variables[i]['page']] = dict()
            mapping[variables[i]['page']][LSBstring] = {'name':variables[i]['name'], 'bytes':variables[i]['bytes']}
        return mapping

    # Debug routine to make sure we've got some good page definitions from our ec2 variables file
    def log_pages(self, count=None):
        i = 0
        for var in self.ecu_mappings.values():
            logging.info(pprint.pformat(var))
            i = i + 1
            if((count != None) and (i > count)):
                break

    def bind(self):
        #self.socket.set_opts(0x480, frame_txtime=0) # 0x400 NOFLOW_MODE, 0x80 FORCESTMIN
        #self.socket.bind("can0", isotp.Address(isotp.AddressingMode.Normal_29bits, ))
        return True


    # Add a variable to interogate on the ECU (frequency of requests not currently supported)
    # We do this by creating a dict of pages, then put all the vars we want to follow as an ordered (lsb) list in each pages
    # ... that list will then be the vars that are constructed into a compound request to the ECU
    def add_variable_to_follow(self, name, frequency=None):
        # Is the name at least non-None
        if (name == None):
            logging.warning(f"Unable to add variable where name is None")
            return False

        # And make sure it's of type "string"
        if (not isinstance(name, str)):
            logging.warning(f"Unable to add non-string {name}")
            return False

        # Check to make sure this name has an entry in our ec2 dictionary of variables
        try:
            variable = self.ecu_variables[name]
        except:
            logging.warning(f"Unable to add variable to follow because we don't have an ec2 definition for {name}")
            return False

        # Set up some commonly accessed params
        page = self.ecu_variables[name]['page']
        lsb = self.ecu_variables[name]['address'][-2:]
        bytes = self.ecu_variables[name]['bytes']

        # Test to see if this page already exists and if not add an empty list
        try:
            temp = self.ecu_vars_to_follow[page]
        except:
            self.ecu_vars_to_follow[page] = list()

        # Find where to insert in the list
        insert_position = 0
        for i, val in enumerate(self.ecu_vars_to_follow[page]):
            # Make sure this isn't a duplicate
            if (self.ecu_vars_to_follow[page][i]['lsb'] == lsb):
                logging.warning(f"Unable to add {name} as duplicate")
                return False
            insert_position = i + 1
            logging.debug(f"Checking:{i} {int(lsb,16)} ({lsb}) {int(self.ecu_vars_to_follow[page][i]['lsb'],16)} ({self.ecu_vars_to_follow[page][i]['lsb']})")
            if (int(self.ecu_vars_to_follow[page][i]['lsb'],16) > int(lsb,16)):
                insert_position = i
                #logging.info(f"Adding {lsb} at position {insert_position}, before {self.ecu_vars_to_follow[page][i]['lsb']}")
                break

        # Now insert this entry into the page's list
        self.ecu_vars_to_follow[page].insert(insert_position, {
                'name':name,
                'bytes': bytes,
                'lsb':lsb,
                'frequency':frequency
            })

        logging.debug(f"Added {lsb} at position {insert_position}")
        return True

    # Add a list of variables to interogate on the ECU (frequency of requests not currently supported)
    def add_variable_list_to_follow(self, name_list, frequency=None):
        count = 0
        for i in name_list:
            if (self.add_variable_to_follow(i), frequency):
                count = count + 1
        logging.debug(pprint.pformat(self.ecu_vars_to_follow))
        return count

    def create_data_request(self, page_name, page):
        request_string = ""
        for item in page:
            logging.debug(pprint.pformat(item, width=120))
            lsb_int = int(item['lsb'],16)
            for i in range(0,int(item['bytes'])):
                request_string = request_string + '{:^2s}'.format(f'{lsb_int+i:02x}')
        request_string = "0100000000" + page_name[2:] + request_string
        logging.debug(f"Request string:{request_string}")
        return binascii.unhexlify(request_string)

    def process_data_response(self, response, vars_to_follow):
        #81aaaa1600
        logging.debug(hex(int.from_bytes(response, byteorder='big', signed=False)))
        data_length = len(response)
        if (data_length < 2):
            logging.debug(f"Response data of length {data_length} is too short")
            return None
        if (response[0] != 0x81):
            logging.debug(f"Response data needs to have a 1st byte of 0x81, we got {hex(response[0])}")
            return None
        i = 1
        response_count = 1
        results = dict()
        for var in vars_to_follow:
            #logging.debug(pprint.pformat(var))
            name = var['name']
            bytes = int(var['bytes'])
            value = bytearray()
            for j in range(0,bytes):
                #logging.debug(hex(response[i+j]))
                value.insert(0,response[i+j])
            #logging.debug(value)
            variable = self.ecu_variables[name]
            scale = float(variable['scale_maximum']) - float(variable['scale_minimum'])
            dividend = (2 ** (bytes * 8)) - 1
            response_int = int.from_bytes(value, byteorder='big', signed=False)
            response_scaled = ((float(response_int * scale)) / float(dividend)) + float(variable['scale_minimum'])
            offset = float(variable['scale_minimum'])
            #logging.debug(f"{name}={response_scaled:.5} {variable['units']} ({variable['short_desc']} ) [{binascii.hexlify(value)}, Scale:{scale}, Div:{dividend}, Offset:{offset:.3}]")
            results[name] = {'name': name, 'value':response_scaled, 'short_desc':variable['short_desc'], 'units':variable['units']}

        return results

    def process_all_pages(self, results):
        if (not isinstance(results, dict )):
            return False

        for page in self.ecu_vars_to_follow:
            command = self.create_data_request(page, self.ecu_vars_to_follow[page])
            logging.info(pprint.pformat(command))

            #self.socket.send(command)

            #response = self.socket.recv()

            # Some dummy data for RT_ENGINESPEED
            response = b'\x81\x34\x12'

            page_results = self.process_data_response(response, self.ecu_vars_to_follow[page])

            # If there's already an entry for this variable in the results array then just update the value
            # Otherwise add a new entry to the results dictionary
            for var, result in page_results.items():
                #logging.debug(pprint.pformat(result))
                try:
                    results[result['name']]['value'] = result['value']
                except:
                    results[result['name']] = {'name': result['name'], 'value':result['value'], 'short_desc':result['short_desc'], 'units':result['units']}


        return results