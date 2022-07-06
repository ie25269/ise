import requests, sys, os
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import base64
import xmltodict
import pprint
import ipaddress

# Retrieves session data from Cisco ISE MNT node for a 
# specific endpoint via mac-address or ip-address.
# Login credentials and ISE server info set via environment variables.
# USAGE: python getsession.py <mac-addr|ip-addr>
 
def valid_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except:
        return False

env1 = "ISE_USER"
env2 = "ISE_PASS"
env3 = "ISE_PSN"
env4 = "ISE_MNT"
if env1 in os.environ:
    username = os.environ.get(env1)
if env2 in os.environ:
    password = os.environ.get(env2)
if env3 in os.environ:
    isePsn = os.environ.get(env3)
if env4 in os.environ:
    iseMnt = os.environ.get(env4)

addr = sys.argv[1].upper()

creds = str.encode(':'.join((username, password)))
encodedAuth = bytes.decode(base64.b64encode(creds))
myHeaders = {
    'accept': "application/xml",
    'content-type': "application/xml",
    'authorization': " ".join(("Basic",encodedAuth)),
    'cache-control': "no-cache",
    }

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
ise = requests.session()
ise.auth = (username, password)
ise.verify = False
ise.disable_warnings = False
ise.timeout = 5
isePort = '443'

# Set url based on argument provided.
if valid_ip(addr):
    url = 'https://{0}:{1}/admin/API/mnt/Session/EndPointIPAddress/{2}'.format(iseMnt,isePort,addr)
else:
    url = 'https://{0}:{1}/admin/API/mnt/Session/MACAddress/{2}'.format(iseMnt,isePort,addr)

res = ise.get(url, headers=myHeaders, verify=False)
headers = res.headers
content = res.content
data = xmltodict.parse(content)
statcode = res.status_code
print(f'\n')
result = {}
# Copy desired results into new result dict.
if 'sessionParameters' in data:
    subdata = data['sessionParameters']
    if 'framed_ip_address' in subdata:
        result['framedIP'] = subdata['framed_ip_address']
    if 'calling_station_id' in subdata:
        result['callingStationID'] = subdata['calling_station_id']
    if 'user_name' in subdata:
        result['userName'] = subdata['user_name']
    if 'endpoint_policy' in subdata:
        result['epPolicy'] = subdata['endpoint_policy']
    if 'authentication_method' in subdata:
        result['authNmeth'] = subdata['authentication_method']
    if 'authentication_protocol' in subdata:
        result['authProtocol'] = subdata['authentication_protocol']
    if 'selected_azn_profiles' in subdata:
        result['authZmeth'] = subdata['selected_azn_profiles']
    if 'dacl' in subdata:
        result['dacl'] = subdata['dacl']
    if 'identity_store' in subdata:
        result['authStore'] = subdata['identity_store']
    if 'identity_group' in subdata:
        result['identityGroup'] = subdata['identity_group']
    if 'cts_security_group' in subdata:
        result['ctsSecurityGroup'] = subdata['cts_security_group']
    if 'network_device_name' in subdata:
        result['netDeviceName'] = subdata['network_device_name']
    if 'location' in subdata:
        result['location'] = subdata['location']
    if 'cpmsession_id' in subdata:
        result['cpmSessionID'] = subdata['cpmsession_id']
    if 'auth_id' in subdata:
        result['AuthID'] = subdata['auth_id']
    '''
    if 'other_attr_string' in subdata:
        other = str(subdata['other_attr_string'])
        other = other.replace(':!:','',1)
        print(f'{other}\n---\n')
    ''' 

print(f'\n\n')
#Print results dict 
for k,v in result.items():
    print(f'{k:<20}: {v}')
print(f'\n--------------------')
print(f'StatusCode: {statcode}')
print(f'{url}\n\n')


