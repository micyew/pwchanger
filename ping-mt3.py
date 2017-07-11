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
import re
import subprocess
from multiprocessing import Lock, Process, Queue, Pool
from do_latency import pyping
from datetime import datetime

def statseeker_export(username,password):
    """ Grab all network devices from Statseeker.
        The API URL contains the following:
        - Uses the base v5 API
        - Uses the cdt_device object
        - Returns the name, IP address, and SNMP Description fields
        - Returns only devices where SNMP and ICMP polling are enabled
        - Returns only devices from groups 23, 26, 161562, and 161563:
            - 23 = Juniper All
            - 26 = Cisco All
            - 161562 = Foundry All
            - 161563 = Brocade All 
        - Uses "limit 0" to return all devices (pagination off)
        - Does not display links. Should not matter but makes debug
            printing of the API call result much easier to read

        Cuts the SNMP Description down to just the first word to define vendor

        Iterates through the results and dumps the name, ipaddress and vendor 
        into a list of dicts.

        Since we're using the napalm library, we also need to either classify the
        device type as either ios or junos. 
    """    
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
    """ Grab a list of currently down devices in Statseeker
        There's no point in attempting to connect to known-down devices
        This API call unfortunately doesn't seem to allow for filtering 
        by group, so this grabs the entire list - even items that are not
        on our 'unreachable' list on our dashboard. Therefore this list
        will always be significantly larger than the list on the dashboard.
    """
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

def ping_udp(host):
    """ Simple UDP Ping
        Uses Digital Ocean's pyping since the official
        does not work in Python3
        Using UDP to bypass sudo requirements.
    """
    return pyping.ping(host, udp=True) != None

def ping_cli(host):
    """ Ping the address/hostname
        return True if packet loss is less than 60%. 

        All other results return False or print and error.

        Code "borrowed" from @tyler_k
    """
    exp = re.compile(r"\s(\d{1,3})\%\s")
    try:
        test = subprocess.Popen(["ping", "-c 5", "-W 2", host],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, error = test.communicate()
        if out:
            stats = re.search(exp, out.decode('utf-8'))
            loss = int(stats.group(1))

            return loss <= 60

        else:
            return False

    except subprocess.CalledProcessError:
        return False

def ping_tcp(host, port):
    """ Does a TCP 'ping'
        Simply attempts a socket connection on the specified port
        22 = SSH
        23 = Telnet
        Timeout is 1 second
        Code "borrowed" from yantisj
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((host, int(port)))
        s.shutdown(socket.SHUT_RD)
        return True
    except:
        return False

def worker(device):
    """ Does the actual work
        First, attempts a TCP 'ping' on port 22 (SSH)
        If that fails, attempts on port 23 (Telnet)
        Dumps the result into a dict
        Returns that dict
    """
    ssh_result = False
    telnet_result = False
    ssh_result = ping_tcp(device['ipaddress'], port=22)
    if not ssh_result:
        telnet_result = ping_tcp(device['ipaddress'], port=23)
    result_dict = {
                'name': device['name'], 
                'ipaddress': device['ipaddress'], 
                'ssh_result': ssh_result, 
                'telnet_result': telnet_result
                }
    return result_dict

def handler(device_list):
    """ Sets up the multiprocessing pools
        Sends the device_list to the worker() function
        Adds the dict passed by the worker() function to a result_list lict
        Returns the result_list lict
    """
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

    ssh_list = list(filter(lambda x: x['ssh_result'] != False, result_list))
    telnet_list = list(filter(lambda x: x['telnet_result'] != False, result_list))
    failed_list = list(filter(lambda x: x['ssh_result'] == False and x['telnet_result'] == False, result_list))

    for failed in failed_list:
        try:
            result_ping = False
            result_ping = ping_cli(failed['ipaddress'])
        except Exception as e:
            print('Failed', e)
        finally:
            print(f"{failed['name']:25}{failed['ipaddress']:20}{str(result_ping):10}")

    print('='*100)
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