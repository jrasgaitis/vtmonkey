#! /usr/bin/python

# A quick fun dirty script- Virus Total API lookup for a list of MD5 hashes and output resultes into a JSON file.
# Useage - vtmonkey.py 'filename' of MD5 hashes
# You may need to mess with the regex for your needs.
# Make sure to add your own private VT API key. The script sends 4 request/minute based on the limitaion set by VT.

import re
import requests
import time
import json
import sys

vtkey = 'add-your-vt-apikey-here'

if len(sys.argv) == 1:
    print('No arguments passed. Filename needed!')
    sys.exit()

increment_count = 4
f = open(sys.argv[1], 'r')
# Feed the file text into findall(); it returns a list of all the found strings
strings = re.findall(r'[a-f0-9]{32}', f.read())
for line in zip(*[iter(strings)] * increment_count):
    print (line), ('\n' * 2)
    time.sleep(60)
    for hash in line:
        print hash
        params = {'apikey': vtkey, 'resource': hash}
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip,  My Python requests library example client or username"
        }
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                                params=params, headers=headers)
        json_response = response.json()
        print params
        print (json_response), ('\n' * 5)
        with open('vt_results.json', 'a') as outfile:
            json.dump(json_response, outfile, sort_keys=True, indent=4,
                      ensure_ascii=False)
