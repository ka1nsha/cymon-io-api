#!/bin/python3
import requests
import ipaddress
import tldextract
# API Methods
# http://docs.cymon.io/
ENDPOINT = "https://api.cymon.io/v2"


class Threats(object):
    def __init__(self, scanType,header, ip):
        url = "https://api.cymon.io/v2/ioc/search/{}/{}".format(scanType,ip)
        self.apireq = requests.api.get(url, headers=header).json()

    def __init__(self, scanType,header, ip, startDate="", endDate=""):
        url = "https://api.cymon.io/v2/ioc/search/{}/{}?startDate={}&endDate={}".format(scanType,ip,startDate,endDate)
        self.apireq = requests.api.get(url, headers=header).json()

    @property
    def allhits(self):
        return self.apireq['total']

    @property
    def gethits(self, id):
        if id is int:
            return self.apireq['hits'][id]
        else:
            return None

    @property
    def allfeedsource(self):
        return [i['link'] for i in self.apireq['hits']]

    @property
    def json(self):
        return self.apireq

    def __str__(self):
        return str(self.apireq)

class Cymon(object):
    def __init__(self,api_key):
        self.api_key = api_key
        self.headers = {"Accept": "application/json", "Authorization": "Bearer " + self.api_key}

    def Threats(self, str):

        if self.isIP(str):
            return Threats("ip", self.headers, str)
        if self.isDomain(str):
            return Threats("domain", self.headers, str)
        else:
            return Threats(self.whichCrypto(str), self.headers, str)

    def isIP(self,ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def isDomain(self,str):
        tld = tldextract.extract(str)
        if tld.registered_domain:
            return True
        else:
            return False

    def whichCrypto(self,str):
        if len(str) == 32:
            return "md5"
        elif len(str) == 40:
           return  "sha1"
        else:
            return "sha256"