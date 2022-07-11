import requests, sys, os
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import base64
import xmltodict
import pprint
###############################
# REAUTH_TYPE_DEFAULT = 0
# REAUTH_TYPE_LAST = 1
# REAUTH_TYPE_RERUN = 2
###############################
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
try:
    mac = sys.argv[1].upper()
except:
    print(f'\nERROR: Must supply argument - MACaddr\n')
    sys.exit(1)


# base64 encode auth strings from ARGs
creds = str.encode(':'.join((username, password)))
encodedAuth = bytes.decode(base64.b64encode(creds))
myHeaders = {
    'authorization': " ".join(("Basic",encodedAuth)),
    'cache-control': "no-cache",
    }
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
ise = requests.session()
ise.verify = False
ise.disable_warnings = False
ise.timeout = 5

url = 'https://{0}/admin/API/mnt/CoA/Reauth/{1}/{2}/2'.format(iseMnt,isePsn,mac)
res = ise.get(url, headers=myHeaders, verify=False)
headers = res.headers
status = res.status_code
content = res.content
data = xmltodict.parse(content)
result = data['remoteCoA']['results']

#print(f'\n{headers}')
print(f'-----')
print(f'Status Code: {status}\nRemoteCoA Results: {result}\nurl: {url}')
print(f'-----\n')
#pprint.pprint(data, indent=2)



