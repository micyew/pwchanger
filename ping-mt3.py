#!.venv/bin/python

""" Requirements:
    - Python >=3.6 (because of the extensive use of f-strings)
    - Requests
    - Napalm
"""
import requests
import json
import credentials
import socket
from multiprocessing import Lock, Process, Queue, Pool
from do_latency import pyping
from datetime import datetime

def statseeker_export(username,password):
    requests.packages.urllib3.disable_warnings()
    headers = {'Accept':'application/json', 'Content-Type':'application/json'}
    urlbase = 'https://statseeker.sempra.com/api/latest/cdt_device/'
    fields  = '?fields=name,.ipaddress,SNMPv2-MIB.sysDescr'
    filters = '&.snmp_poll_filter=IS(\u0027on\u0027)&.ping_poll_filter=IS(\u0027on\u0027)'
    links   = '&links=none'
    limit   = '&limit=0'
    groups  = '&groups=23,26,161562,161563'
    url = urlbase + fields + filters + links + limit

    devices = requests.get(url, headers=headers, auth=(username, password), verify=False).json()

    device_types = ['Juniper', 'Cisco', 'Brocade', 'Foundry']
    device_list = []

    for device in devices['data']['objects'][0]['data']:
        if device['SNMPv2-MIB.sysDescr']:
            if any(x in device['SNMPv2-MIB.sysDescr'] for x in device_types):
                tempdict = {}
                tempdict['name'] = device['name']
                tempdict['ipaddress'] = device['.ipaddress']
                tempdict['vendor'] = device['SNMPv2-MIB.sysDescr'].split()[0]
                if tempdict['vendor'] == "Juniper": 
                    tempdict['napalm_driver'] = "junos"
                else:
                    tempdict['napalm_driver'] = "ios"
                device_list.append(tempdict)
    return device_list

def do_ping(host):
    """"""
    return pyping.ping(host, udp=True) != None

def do_tcp_ping(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((host, int(port)))
        s.shutdown(socket.SHUT_RD)
        return True
    except:
        return False

def worker(device):
    result = do_tcp_ping(device['ipaddress'], port=22)
    result_dict = {'name': device['name'], 'ipaddress': device['ipaddress'], 'result': result}
    return result_dict

def handler(device_list):
    result_list = []
    pool = Pool(processes=32)
    for result_dict in pool.imap(worker, device_list):
        result_list.append(result_dict)
    return result_list

def main():
    """"""
    startTime = datetime.now()
    
    device_list = statseeker_export(credentials.statseeker_username,credentials.statseeker_password)
    
    result_list = handler(device_list)

    print(f"\nItems processed: {len(result_list)}")
    
    print(f"\n*** It took: {datetime.now() - startTime} to execute this script ***")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nCTRL+C Pressed. Exiting.\n\n")
        pass
exit()