#!/.pyenv/versions/3.7.2/bin/python
"""Module docstring."""

TOKENURL = "/api/tokenservices"
GETNATRULEURL = "/api/nat/before"
GETOBJECTIDURL = "/api/objects/networkobjects/{0}"
GETOBJECTGROUPURL = "/api/objects/networkobjectgroups/{0}"
LOGOFFURL = "/api/tokenservices/{0}"
BASEURL = "https://{0}"

def get_headers(api_token):
    return {
        "content-type": "application/json",
        "X-Auth-Token": api_token,
        "cache-control": "no-cache"}

def get_base_headers():
    return {
        "content-type": "application/json",
        "cache-control": "no-cache"}

def get_token_url():
    return TOKENURL

def get_natrule_url():
    return GETNATRULEURL

def get_objectID_url(obj_ID):
    return GETOBJECTIDURL.format(obj_ID)

def get_objectgroupID_url(obj_ID):
    return GETOBJECTGROUPURL.format(obj_ID)

def logoff_token(api_token):
    return LOGOFFURL.format(api_token)

def get_baseURL(fw_ip):
    return BASEURL.format(fw_ip)
