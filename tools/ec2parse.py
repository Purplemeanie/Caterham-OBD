# ec2parse
# Takes an MBE EC2 ECu file, parses the data and then 
# outputs to a preferred filetype
#
# 2019-08-18 John Martin
#

import logging
import argparse
import re
import csv
import json
import pprint

version = "0.2"

# Setup and parse command line args
parser = argparse.ArgumentParser(prog='ec2parse', description='Takes and EC2 file and converts to a python dict')
parser.add_argument('--input',         '-i',                   help='Input EC2 filename', required=True)
parser.add_argument('--output',        '-o',                   help='Output file (.csv, .json, .py)', required=True)
parser.add_argument('--version',       '-V', action='version', version='%(prog)s '+version)

args = parser.parse_args()

if args.input == None:
    parser.print_help()
    exit()

if args.output == None:
    parser.print_help()
    exit()

# Check we've got a good option for file output
temp_output = args.output.split(".")
output_file_extension = temp_output[len(temp_output)-1].lower()

if(not (output_file_extension == "csv" or output_file_extension == "json" or output_file_extension == "py")):
        print("Output file extension must be one of (.csv, .json, .py)")
        parser.print_help()
        exit()

print(f"Using file: {args.input} with output extension {output_file_extension}")

# Open file
ec2_file = open(args.input, "r")

# Read all the file into a list
ec2_file_list = ec2_file.readlines()

# Iterate through file looking for [<SECTION_NAME>] [end <SECTION_NAME>] pairs]
# Find the "[end <>]" of sections first
# HISTORY
# PROPERTIES
# PARAMETER PROTOTYPES
# NUMERIC SCALES
# STRING SCALES
# PARAMETER DEFINITIONS
# COLLECTIONS
# ALARMS
# SPECIAL FUNCTIONS
# MAPPING VECTORS
# MAPPING CONTROLS
# SETUP PROTOTYPES
# SETUP DEFINITIONS
# MAP PROGRAMS
# VARIANTS
# SPECIAL INTERFACE PROTOTYPES
# MATRICES

section_names = dict()

for i, val in enumerate(ec2_file_list): 
  m = re.search('\[end\s([^\]]*)\]', val) # \w\s\(\)_
  if ( m ):
    section_names[m[1]] = {"end":i}

# Now find the matching section names
for i, val in enumerate(ec2_file_list): 
  m = re.search('\[([\w\s\(\)_]*)\]', val)
  if ( m and section_names.get(m[1])):
    section_names[m[1]]['start'] = i

#print(section_names.keys())
print(f"There are {len(section_names.keys())} sections")

# Get all the variable names, page, address and byte width
# [RT_ENGINESPEED]
# Number of Dimensions = 0
# Page = F8
# Address = 237C
# Bytes per Cell = 2
# 0 = SCALE_ENGINESPEED
# Precision = 0

variable_names = dict()
variable_name = ''
variable_param_mapping = dict(
  {"Number of Dimensions":"dimensions",
   "Page":"page",
   "Address":"address",
   "Bytes per Cell":"bytes",
   "0":"scale0",
   "1":"scale1",
   "2":"scale2",
   "Precision":"precision",
   "Signed":"signed",
   "Variant Title":"variant_title",
   "Sector":"sector",
   "Main":"main",
   "Trim":"trim",
   "Data Class":"class",
   "Parameter 1":"parameter1",
   "Parameter 2":"parameter2",
   "Index 1":"index1",
   "Index 2":"index2",
   "Dummy Variable":"dummy",
   "Proteaus":"proteaus",
   "Proteaus Colour":"proteaus_colour"
  })

for i in range(section_names['PARAMETER DEFINITIONS']['start']+1, section_names['PARAMETER DEFINITIONS']['end']):
  # Find variable names
  m = re.match('\[([^\]]*)\]', ec2_file_list[i]) # \w\s\)\(
  if( m ):
    variable_names[m[1]] = {'name':m[1]}
    variable_name = m[1]
  else:
    #Find others of form x = y
    m = re.match('([\w\s]*) = ([^\=]*)', ec2_file_list[i])
    if( m ):
      val = m[2].strip('\n')
      #print(f"Found {m[1]}({variable_param_mapping[m[1]]})={val} for {variable_name}")
      variable_names[variable_name][variable_param_mapping[m[1]]] = val

#print(variable_names['RT_ENGINESPEED'])
print(f"There are {len(variable_names.keys())} variables")

# Get all the scaling information for each var
# [SCALE_USERENGINEOFFSET]
# Units = �
# Scale Minimum = -360.000000
# Scale Maximum = 360.000000
# Display Minimum = -360.000000
# Display Maximum = 360.000000
# Display Interval = 60.000000
# Precision = 1

# [SCALE_ENGINESPEED]
# Units = RPM
# Scale Minimum = 0.000000
# Scale Maximum = 65535.000000
# Display Minimum = 0.000000
# Display Maximum = 12000.000000
# Display Interval = 1000.000000

scale_names = dict()
scale_name = ''
scale_param_mapping = dict(
  {"Scale Minimum":"scale_minimum",
   "Scale Maximum":"scale_maximum",
   "Scale Interval":"scale_interval",
   "Scale Points":"scale_points",
   "Display Minimum":"display_minimum",
   "Display Maximum":"display_maximum",
   "Display Interval":"display_interval",
   "Display Points":"display_points",
   "Precision":"precision",
   "Units":"units"
  })
for i in range(section_names['NUMERIC SCALES']['start']+1, section_names['NUMERIC SCALES']['end']):
  # Find scale names
  m = re.match('\[([^\]]*)\]', ec2_file_list[i])
  if( m ):
    scale_names[m[1]] = dict() #{'name':m[1]}
    scale_name = m[1]
  else:
    #Find others of form x = y
    m = re.match('([\w\s]*) = ([\w\s\-\.]*)', ec2_file_list[i])
    if( m ):
      val = m[2].strip('\n')
      #print(f"Found {m[1]}({scale_param_mapping[m[1]]})={val} for {scale_name}")
      scale_names[scale_name][scale_param_mapping[m[1]]] = val

#print(scale_names['SCALE_ENGINESPEED'])
#print(scale_names['SCALE_USERENGINEOFFSET'])
print(f"There are {len(scale_names.keys())} scales")
  
# Get description info for each var
#PARAMETER PROTOTYPES
for i in range(section_names['PARAMETER PROTOTYPES']['start']+1, section_names['PARAMETER PROTOTYPES']['end']):
  comma_sep = ec2_file_list[i].split(',')
  disabled = ""
  short_desc = ""
  long_desc = ""
  for i in range(0, len(comma_sep)):
      if(i == 0):
        variable = comma_sep[0].strip('\n')
      elif(i == 1):
        short_desc = comma_sep[1].strip('\n')
      elif(i == 3):
        long_desc = comma_sep[3].strip('\n')
      elif(i == 4):
        disabled = comma_sep[4].strip(' \n')
        #print(f"{variable} is {disabled}")
  if (len(comma_sep) >= 4):
    #variable = comma_sep[0].strip('\n')
    #short_desc = comma_sep[1].strip('\n')
    #long_desc = comma_sep[3].strip('\n')
    #disabled = comma_sep[4].strip('\n')
    #print(f"{variable}, {short_desc}, {long_desc}")
    variable_names[variable]['short_desc'] = short_desc
    variable_names[variable]['long_desc'] = long_desc
    variable_names[variable]['disabled'] = disabled # Disabled here means we won't output it later
  elif (len(comma_sep) > 1):
    print(comma_sep)
    exit()

# Lets create an output array
if (output_file_extension == "csv"):
    output_list = list()
    for key, variable in variable_names.items():
      # Only output SCALE (numeric) values at the moment, not STRING
      if (variable['scale0'][:5] == 'SCALE'):
        scale = scale_names[variable['scale0']]
        output_list.append({ 
          'name':variable['name'],  
          'page':"0x"+variable['page'].lower(),  
          'address':"0x"+variable['address'].lower(),
          'bytes':variable['bytes'],
          'disabled':variable['disabled'], # We do output disabled fields with csv
          'scale_minimum':scale['scale_minimum'],
          'scale_maximum':scale['scale_maximum'],
          'display_minimum':scale['display_minimum'],
          'display_maximum':scale['display_maximum'],
          'display_interval':scale['display_interval'],
          'units':scale['units'],
          'short_desc':variable['short_desc'],
          'long_desc':variable['long_desc']
        })
    print(f"Outputing {len(output_list)} variables in {output_file_extension} format")
else:
    output_dict = dict()
    for key, variable in variable_names.items():
      # Only output SCALE (numeric) values at the moment, not STRING
      if (variable['scale0'][:5] == 'SCALE' and str(variable['disabled']).lower() != "disabled"):
        scale = scale_names[variable['scale0']]
        output_dict[variable['name']] = { 
          'name':variable['name'],  
          'page':"0x"+variable['page'].lower(),  
          'address':"0x"+variable['address'].lower(),
          'bytes':variable['bytes'],
          'scale_minimum':scale['scale_minimum'],
          'scale_maximum':scale['scale_maximum'],
          'display_minimum':scale['display_minimum'],
          'display_maximum':scale['display_maximum'],
          'display_interval':scale['display_interval'],
          'units':scale['units'],
          'short_desc':variable['short_desc'],
          'long_desc':variable['long_desc']
          }
    print(f"Outputing {len(output_dict)} variables in {output_file_extension} format")
      
      
# And now output it in whatever format we want...
if (output_file_extension == "csv"):
    with open(args.output, 'w') as f:  # Just use 'w' mode in 3.x
        w = csv.DictWriter(f, output_list[1].keys(), quotechar='"', quoting=csv.QUOTE_ALL)
        w.writeheader()
        w.writerows(output_list)
elif (output_file_extension == "json"):
    #json_output_string = json.dumps(output_list, indent=4, separators=(". ", " = "))
    json_output_string = json.dumps(output_dict)
    with open(args.output, 'w') as f:
        f.write(json_output_string)
elif (output_file_extension == "py"):
    with open(args.output, 'w') as f:
        pprint.pprint(output_dict, stream=f, indent=4, width=80, depth=None, compact=False)
