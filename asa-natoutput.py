#!/Users/apeterson/.pyenv/versions/3.7.2/bin/python
"""Module docstring."""
# pylint: disable= W0601, E0611, W0702, W0622, W0235, E1101, E1305, W0201, C0103, R0902, R0903, R1702, C0301, R0915
# This disables erronious pylint errors.
import json
import ssl
import time
import requests
import urllib3
import csv
import os
import traceback
import argparse
import env_vars
from requests.auth import HTTPBasicAuth

ssl._create_default_https_context = ssl._create_unverified_context

urllib3.disable_warnings()  # Suppresses warnings from unsigned Cert warning.


def get_token(fw_ip, keyuname, keypasswd):
    """POSTs to REST API Agent to retrieve AUTH Token.
    Returns:
        [str] -- [Post returns JSON, which is converted to str and returned.]
    """
    url = env_vars.get_baseURL(fw_ip) + env_vars.get_token_url()
    print(url)
    headers = {
        'content-type': "application/json",
        'cache-control': "no-cache"}
    response = requests.post(url, verify=False, stream=True, auth=HTTPBasicAuth(keyuname, keypasswd), headers=headers)
    getstatuscode = response.status_code
    resp_headers = response.headers
    token = resp_headers.get('X-Auth-Token', default=None)
    if getstatuscode == 204:
        return token
    else:
        try:
            errorresponse = response.json()
            print("Error: {}.  {}.\n".format(
                errorresponse["messages"][0]["code"], errorresponse["messages"][0]["details"]))
        except:
            response.raise_for_status()

def get_natrule(fw_ip, api_token, num):
    """Retrieves NATs from Cisco ASA REST API Agent.
    Arguments:
        xauthresponsetoken {[str]} -- [AUTH Token for authentication.]
        num {[int]} -- [Used for iterations in loop.]
    Returns:
        [str] -- JSON output from Device API.
    """
    url = env_vars.get_baseURL(fw_ip) + env_vars.get_natrule_url()
    index = {
        "offset": num,}
    response = requests.get(url, verify=False, headers=env_vars.get_headers(api_token), params=index)
    getstatuscode = response.status_code
    if getstatuscode == 200:
        try:
            responseJSON = response.json()
            return responseJSON
        except:
            return response
    else:
        try:
            errorresponse = response.json()
            print("Error: {}.  {}.\n".format(
                errorresponse["messages"][0]["code"], errorresponse["messages"][0]["details"]))
        except:
            response.raise_for_status()

def get_natrange_info(fw_ip, api_token):
    """Method to GET NAT from API.
    Arguments:
        xauthresponsetoken {[str]} -- [AUTH Token for authentication.]
    Returns:
        [json] -- JSON NAT Output.
    """
    url = env_vars.get_baseURL(fw_ip) + env_vars.get_natrule_url()
    response = requests.get(url, verify=False, headers=env_vars.get_headers(api_token))
    getstatuscode = response.status_code
    if getstatuscode == 200:
        try:
            responseJSON = response.json()
            return responseJSON
        except:
            return response
    else:
        try:
            errorresponse = response.json()
            print("Error: {}.  {}.\n".format(
                errorresponse["messages"][0]["code"], errorresponse["messages"][0]["details"]))
        except:
            response.raise_for_status()

def get_objectGroupId(fw_ip, api_token, obj_ID):
    """Method to GET json output from related ObjectId.
    Arguments:
        xauthresponsetoken {[str]} -- [AUTH Token for authentication.]
        objectGroupInput {[type]} -- [description]
    Returns:
        [type] -- [description]
    """
    url = env_vars.get_baseURL(fw_ip) + env_vars.get_objectgroupID_url(obj_ID)
    response = requests.get(url, verify=False, headers=env_vars.get_headers(api_token))
    getstatuscode = response.status_code
    if getstatuscode == 200:
        try:
            responseJSON = response.json()
            return responseJSON
        except:
            return response
    else:
        try:
            errorresponse = response.json()
            print("Error: {}.  {}.\n".format(
                errorresponse["messages"][0]["code"], errorresponse["messages"][0]["details"]))
        except:
            response.raise_for_status()

def get_objectId(fw_ip, api_token, obj_ID):
    """Method to GET json output from related ObjectId.
    Arguments:
        xauthresponsetoken {[str]} -- [AUTH Token for authentication.]
        objectInput {[type]} -- [description]
    Returns:
        [type] -- [description]
    """
    url = env_vars.get_baseURL(fw_ip) + env_vars.get_objectID_url(obj_ID)
    response = requests.get(url, verify=False, headers=env_vars.get_headers(api_token))
    getstatuscode = response.status_code
    if getstatuscode == 200:
        try:
            responseJSON = response.json()
            return responseJSON
        except:
            return response
    else:
        try:
            errorresponse = response.json()
            print("Error: {}.  {}.\n".format(
                errorresponse["messages"][0]["code"], errorresponse["messages"][0]["details"]))
        except:
            response.raise_for_status()

def logout(fw_ip, api_token, keyuname, keypasswd):
    """Method DELETES AUTH Token when application is done.
    Arguments:
        xauthresponsetoken {[str]} -- [AUTH Token for authentication.]
    Returns:
        [json] -- [Response output from Logoff API Call.]
    """
    url = env_vars.get_baseURL(fw_ip) + env_vars.logoff_token(api_token)
    response = requests.delete(url, verify=False, stream=True, auth=HTTPBasicAuth(
        keyuname, keypasswd), headers=env_vars.get_base_headers())
    logoutstatuscode = response.status_code
    if logoutstatuscode == 204:
        print("Session logged off.\n")
        return response
    else:
        print("Error while logging session off...\n")
        response.raise_for_status()


def main(keyuname, keypasswd, fw_ip):
    projectpath = os.getenv("WORKSPACE")
    try:
        os.remove('{}/NATOutput.csv'.format(projectpath))
    except OSError as e:
        print(e)
    objectInput = None
    objectGroupInput = None
    lists = ["originalSource", "originalDestination", "translatedSource", "translatedDestination"]
    rowdict = {}
    with open('{}/NATOutput.csv'.format(projectpath), 'w') as csvfile:
        fieldnames = ['position', 'originalSource', 'originalDestination','translatedSource', 'translatedDestination']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        api_token1 = get_token(fw_ip, keyuname, keypasswd)
        rangeNAT = get_natrange_info(fw_ip, api_token1)
        num = rangeNAT["rangeInfo"]["offset"]
        total = rangeNAT["rangeInfo"]["total"]
        while num <= total:
            api_token = get_token(fw_ip, keyuname, keypasswd)
            getnat = get_natrule(fw_ip, api_token, num)
            try:
                for nat in getnat["items"]:
                    rowdict = {"position": (), "originalSource": [], "originalDestination": [], "translatedSource": [], "translatedDestination": []}
                    postemp = str(nat["position"])
                    rowdict['position'] = postemp
                    for i in lists:
                        try:
                            compare = nat[i].get("kind")  #Can't compare nat[i]["kind"] to a String in if statement.
                        except:
                            compare = str(i)
                        if compare == "objectRef#NetworkObjGroup":
                            try:
                                objectGroupInput = nat[str(i)]["objectId"]
                                objectGroupOutput = get_objectGroupId(fw_ip, api_token, objectGroupInput)
                                if objectGroupOutput["objectId"] == "JCONNECT" or objectGroupOutput["objectId"] == "FRAME":
                                    rowdict[str(i)].append(objectGroupOutput["objectId"])
                                else:
                                    for ip in objectGroupOutput["members"]:
                                        temp = str(ip["value"])
                                        rowdict[str(i)].append(temp)
                            except Exception as ee:
                                print(ee)
                        elif compare == "objectRef#NetworkObj":
                            try:
                                objectInput = nat[str(i)]["objectId"]
                                objectOutput = get_objectId(fw_ip, api_token, objectInput)
                                if objectOutput["objectId"] == "JCONNECT" or objectOutput["objectId"] == "FRAME":
                                    rowdict[str(i)].append(objectOutput["objectId"])
                                else:
                                    temp = objectOutput["host"].get("value")
                                    rowdict[str(i)].append(temp)
                            except Exception:
                                print("Network Object Error " + traceback.format_exc())
                        elif compare == "AnyIPAddress":
                            rowdict[str(i)].append(nat[str(i)]["value"])
                        elif compare == "interfaceIP":
                            rowdict[str(i)].append("Interface " + nat[str(i)]["value"])
                        elif compare == "translatedDestination":
                            try:
                                rowdict[str(i)].append(nat[str(i)])
                            except:
                                rowdict[str(i)].append(nat[str(i)]["value"])
                        else:
                            print ("No Object-ID Found for {}.".format(str(i)))
                    writer.writerow(rowdict)
                    rowdict.clear()
            except Exception:
                print(traceback.format_exc())
            print("Number increasing by 100 " + str(num))
            num = num + 100  # API will only pull 100 NATs at a time.
            logout(fw_ip, api_token, keyuname, keypasswd)
            logout(fw_ip, api_token1, keyuname, keypasswd)
    csvfile.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get Vars')
    parser.add_argument("svc_uname")
    parser.add_argument("svc_passwd")
    parser.add_argument("firewallip")
    args = vars(parser.parse_args())
    keyuname = args["svc_uname"]
    keypasswd = args["svc_passwd"]
    fw_ip = args["firewallip"]
    main(keyuname, keypasswd, fw_ip)
