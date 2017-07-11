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

def get_skiplist(username,password):
    """"""
    requests.packages.urllib3.disable_warnings()
    headers = {'Accept':'application/json', 'Content-Type':'application/json'}
    urlbase = 'https://statseeker.sempra.com/api/latest/event/'
    fields  = '?fields=device,description,status&status_formats=time,state'
    filters = '&description_filter==\u0027ping_state\u0027&status_filter==\u0027down\u0027&status_filter_format=state'
    links   = '&links=none'
    limit   = '&limit=0'
    url = urlbase + fields + filters + links + limit

    down_devices = requests.get(url, headers=headers, auth=(username, password), verify=False).json()

    skiplist = []

    for device in down_devices['data']['objects'][0]['data']:
        skiplist.append(device['device'])

    return skiplist

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
    ssh_result = False
    telnet_result = False
    ssh_result = do_tcp_ping(device['ipaddress'], port=22)
    if not ssh_result:
        telnet_result = do_tcp_ping(device['ipaddress'], port=23)
    result_dict = {
                'name': device['name'], 
                'ipaddress': device['ipaddress'], 
                'ssh_result': ssh_result, 
                'telnet_result': telnet_result
                }
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
    skiplist = get_skiplist(credentials.statseeker_username,credentials.statseeker_password)

    device_list = list(filter(lambda x: x['name'] not in skiplist, device_list))

    result_list = handler(device_list)

    sshcount = 0
    telnetcount = 0
    failedcount = 0

    for result in result_list:
        if result['ssh_result']:
            sshcount += 1
        elif result['telnet_result']:
            telnetcount += 1
        else:
            failedcount += 1
            print(f"{result['name']:25}{result['ipaddress']:20}{str(result['ssh_result']):10}{str(result['telnet_result']):10}")

    ssh_list = list(filter(lambda x: x['ssh_result'] != False, result_list))
    telnet_list = list(filter(lambda x: x['telnet_result'] != False, result_list))
    failed_list = 0

    print(f"Devices processed: {len(result_list)}")
    print(f"SSH Devices: {len(ssh_list)}")
    print(f"Telnet Devices: {len(telnet_list)}")
    print(f"Failed Devices: {len(failed_list)}")

    print(f"\n*** It took: {datetime.now() - startTime} to execute this script ***")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nCTRL+C Pressed. Exiting.\n\n")
        pass
exit()