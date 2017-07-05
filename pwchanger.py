#!.venv/bin/python
import requests
import json
import credentials
import napalm

def get_passwords(filename):
    """ Grab passwords from a file and returns a simple list.

        (Passing the file name to this function in case I ever decide 
        to accept the file name from the command line.)
    """
    with open(filename, 'r') as f:
        password_list = [item.strip() for item in f.read().splitlines() if item]
    return password_list

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

def napalm_this_bitch(password_list, name, ipaddress, napalm_driver):
    """"""
    print(f'{name:40}{ipaddress:20}{napalm_driver:10}', end='')
    for password in password_list:
        try:
            if napalm_driver == "ios":
                optional_args = {'dest_file_system':'flash:'}
            elif napalm_driver == "junos":
                optional_args = {}
            driver = napalm.get_network_driver(napalm_driver)
            device = driver(hostname=ipaddress, username='ad-cajones2', password=password, optional_args=optional_args)
            device.open()
            device.close()
            return password
        except:
            pass 

def main():
    """"""
    password_list = get_passwords('passwords_ad.txt')
    device_list = statseeker_export(credentials.statseeker_username,credentials.statseeker_password)
    device_fail_list = []
    print(f'\n{"HOSTNAME":40}{"IP ADDRESS":20}{"DRIVER":10}{"STATUS":10}')
    print('=' * 100)
    for device in device_list:
        password = napalm_this_bitch(password_list, device['name'], device['ipaddress'], device['napalm_driver'])
        if password:
            print(f'{"OK":10}')
        else:
            print(f'{"*** NO PASS ***":10}')
            device_fail_list.append(device)

    print('FAILED DEVICES')
    print('=' * 100)
    for device in device_fail_list:
        print(f"{device['name']:40}{device['ipaddress']:20}{device['vendor']:10}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nCTRL+C Pressed. Exiting.\n\n")
        pass
exit()