import os,re,operator, json, datetime, glob
import statistics 
import seaborn as sns
import pandas as pd
import requests
import csv
import json
import os.path
import matplotlib.pyplot as plt 
import itertools
import numpy as np
import matplotlib.pyplot as plt
from numpy import diff
from pandas import DataFrame
import math
import math
from itertools import accumulate
import matplotlib.pyplot as plt
import matplotlib.style
import matplotlib as mpl
mpl.style.use('default')
import numpy as np
import seaborn as sns
import numpy as np 
import subprocess
import sys
import graphviz
from IPython.display import Image, display
from shutil import copyfile
import json
import re
from collections import defaultdict

IANA_CSV_FILE = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
DB_PATH = "./ports.json"


## ----- 2
from enum import Enum

class MicroAttackStage(Enum) :
    INIT = 0

    TARGET_IDEN = 1
    SURFING = 2
    SOCIAL_ENGINEERING = 3
    HOST_DISC = 4
    SERVICE_DISC = 5
    VULN_DISC = 6
    INFO_DISC = 7

    USER_PRIV_ESC = 10
    ROOT_PRIV_ESC = 11
    NETWORK_SNIFFING = 12
    BRUTE_FORCE_CREDS = 13
    ACCT_MANIP = 14
    TRUSTED_ORG_EXP = 15
    PUBLIC_APP_EXP = 16
    REMOTE_SERVICE_EXP = 17
    SPEARPHISHING = 18
    SERVICE_SPECIFIC = 19
    DEFENSE_EVASION = 20
    COMMAND_AND_CONTROL = 21
    LATERAL_MOVEMENT = 22
    ARBITRARY_CODE_EXE = 23
    PRIV_ESC = 99

    END_POINT_DOS = 100
    NETWORK_DOS = 101
    SERVICE_STOP = 102
    RESOURCE_HIJACKING = 103
    DATA_DESTRUCTION = 104
    CONTENT_WIPE = 105
    DATA_ENCRYPTION = 106
    DEFACEMENT = 107
    DATA_MANIPULATION = 108
    DATA_EXFILTRATION = 109
    DATA_DELIVERY = 110
    PHISHING = 111

    NON_MALICIOUS = 999


class MacroAttackStage(Enum) :
    NONE = 0
    PASSIVE_RECON = 1
    ACTIVE_RECON = 2
    PRIVLEDGE_ESC = 3
    ENSURE_ACCESS = 4
    TARGETED_EXP = 5
    ZERO_DAY = 6
    DISRUPT = 7
    DISTROY = 8
    DISTORT = 9
    DISCLOSURE = 10
    DELIVERY = 11

mapping = {'MicroAttackStage.TARGET_IDEN' : 'MacroAttackStage.PASSIVE_RECON',
       'MicroAttackStage.SURFING': 'MacroAttackStage.PASSIVE_RECON',
       'MicroAttackStage.SOCIAL_ENGINEERING': 'MacroAttackStage.PASSIVE_RECON',
       'MicroAttackStage.HOST_DISC': 'MacroAttackStage.ACTIVE_RECON',
       'MicroAttackStage.SERVICE_DISC': 'MacroAttackStage.ACTIVE_RECON',
       'MicroAttackStage.VULN_DISC': 'MacroAttackStage.ACTIVE_RECON',
       'MicroAttackStage.INFO_DISC': 'MacroAttackStage.ACTIVE_RECON',
       'MicroAttackStage.PRIV_ESC' : 'MacroAttackStage.PRIVLEDGE_ESC',
       'MicroAttackStage.USER_PRIV_ESC': 'MacroAttackStage.PRIVLEDGE_ESC',
       'MicroAttackStage.ROOT_PRIV_ESC': 'MacroAttackStage.PRIVLEDGE_ESC',
       'MicroAttackStage.NETWORK_SNIFFING': 'MacroAttackStage.PRIVLEDGE_ESC',
       'MicroAttackStage.BRUTE_FORCE_CREDS': 'MacroAttackStage.PRIVLEDGE_ESC',
       'MicroAttackStage.ACCT_MANIP': 'MacroAttackStage.PRIVLEDGE_ESC',
       'MicroAttackStage.TRUSTED_ORG_EXP': 'MacroAttackStage.TARGETED_EXP',
       'MicroAttackStage.PUBLIC_APP_EXP': 'MacroAttackStage.TARGETED_EXP',
       'MicroAttackStage.REMOTE_SERVICE_EXP': 'MacroAttackStage.TARGETED_EXP',
       'MicroAttackStage.SPEARPHISHING': 'MacroAttackStage.TARGETED_EXP',
       'MicroAttackStage.SERVICE_SPECIFIC': 'MacroAttackStage.TARGETED_EXP',
       'MicroAttackStage.ARBITRARY_CODE_EXE': 'MacroAttackStage.TARGETED_EXP',
       'MicroAttackStage.DEFENSE_EVASION': 'MacroAttackStage.ENSURE_ACCESS',
       'MicroAttackStage.COMMAND_AND_CONTROL': 'MacroAttackStage.ENSURE_ACCESS',
       'MicroAttackStage.LATERAL_MOVEMENT': 'MacroAttackStage.ENSURE_ACCESS',
       'MicroAttackStage.END_POINT_DOS': 'MacroAttackStage.DISRUPT',
       'MicroAttackStage.NETWORK_DOS': 'MacroAttackStage.DISRUPT',
       'MicroAttackStage.SERVICE_STOP': 'MacroAttackStage.DISRUPT',
       'MicroAttackStage.RESOURCE_HIJACKING': 'MacroAttackStage.DISRUPT',
       'MicroAttackStage.DATA_DESTRUCTION': 'MacroAttackStage.DISTROY',
       'MicroAttackStage.CONTENT_WIPE': 'MacroAttackStage.DISTROY',
       'MicroAttackStage.DATA_ENCRYPTION': 'MacroAttackStage.DISTORT',
       'MicroAttackStage.DEFACEMENT': 'MacroAttackStage.DISTORT',
       'MicroAttackStage.DATA_MANIPULATION': 'MacroAttackStage.DISTORT',
       'MicroAttackStage.DATA_EXFILTRATION': 'MacroAttackStage.DISCLOSURE',
       'MicroAttackStage.DATA_DELIVERY': 'MacroAttackStage.DELIVERY',
       'MicroAttackStage.NON_MALICIOUS': 'MacroAttackStage.NONE',
       }
 
macro = {0: 'MacroAttackStage.NONE', 1: 'MacroAttackStage.PASSIVE_RECON', 2: 'MacroAttackStage.ACTIVE_RECON', 3: 'MacroAttackStage.PRIVLEDGE_ESC', 4: 'MacroAttackStage.ENSURE_ACCESS', 5: 'MacroAttackStage.TARGETED_EXP', 6: 'MacroAttackStage.ZERO_DAY', 7: 'MacroAttackStage.DISRUPT', 8: 'MacroAttackStage.DISTROY', 9: 'MacroAttackStage.DISTORT', 10: 'MacroAttackStage.DISCLOSURE', 11: 'MacroAttackStage.DELIVERY'}
macro_inv = {v: k for k, v in macro.items()}
micro = {0: 'MicroAttackStage.INIT', 1: 'MicroAttackStage.TARGET_IDEN', 2: 'MicroAttackStage.SURFING', 3: 'MicroAttackStage.SOCIAL_ENGINEERING', 4: 'MicroAttackStage.HOST_DISC', 5: 'MicroAttackStage.SERVICE_DISC', 6: 'MicroAttackStage.VULN_DISC', 7: 'MicroAttackStage.INFO_DISC', 10: 'MicroAttackStage.USER_PRIV_ESC', 11: 'MicroAttackStage.ROOT_PRIV_ESC', 12: 'MicroAttackStage.NETWORK_SNIFFING', 13: 'MicroAttackStage.BRUTE_FORCE_CREDS', 14: 'MicroAttackStage.ACCT_MANIP', 15: 'MicroAttackStage.TRUSTED_ORG_EXP', 16: 'MicroAttackStage.PUBLIC_APP_EXP', 17: 'MicroAttackStage.REMOTE_SERVICE_EXP', 18: 'MicroAttackStage.SPEARPHISHING', 19: 'MicroAttackStage.SERVICE_SPECIFIC', 20: 'MicroAttackStage.DEFENSE_EVASION', 21: 'MicroAttackStage.COMMAND_AND_CONTROL', 22: 'MicroAttackStage.LATERAL_MOVEMENT', 23: 'MicroAttackStage.ARBITRARY_CODE_EXE', 99: 'MicroAttackStage.PRIV_ESC', 100: 'MicroAttackStage.END_POINT_DOS', 101: 'MicroAttackStage.NETWORK_DOS', 102: 'MicroAttackStage.SERVICE_STOP', 103: 'MicroAttackStage.RESOURCE_HIJACKING', 104: 'MicroAttackStage.DATA_DESTRUCTION', 105: 'MicroAttackStage.CONTENT_WIPE', 106: 'MicroAttackStage.DATA_ENCRYPTION', 107: 'MicroAttackStage.DEFACEMENT', 108: 'MicroAttackStage.DATA_MANIPULATION', 109: 'MicroAttackStage.DATA_EXFILTRATION', 110: 'MicroAttackStage.DATA_DELIVERY', 111: 'MicroAttackStage.PHISHING', 999: 'MicroAttackStage.NON_MALICIOUS'}
micro_inv = {v: k for k, v in micro.items()}
micro2macro = {'MicroAttackStage.TARGET_IDEN': 'MacroAttackStage.PASSIVE_RECON', 'MicroAttackStage.SURFING': 'MacroAttackStage.PASSIVE_RECON', 'MicroAttackStage.SOCIAL_ENGINEERING': 'MacroAttackStage.PASSIVE_RECON', 'MicroAttackStage.HOST_DISC': 'MacroAttackStage.ACTIVE_RECON', 'MicroAttackStage.SERVICE_DISC': 'MacroAttackStage.ACTIVE_RECON', 'MicroAttackStage.VULN_DISC': 'MacroAttackStage.ACTIVE_RECON', 'MicroAttackStage.INFO_DISC': 'MacroAttackStage.ACTIVE_RECON', 'MicroAttackStage.USER_PRIV_ESC': 'MacroAttackStage.PRIVLEDGE_ESC', 'MicroAttackStage.ROOT_PRIV_ESC': 'MacroAttackStage.PRIVLEDGE_ESC', 'MicroAttackStage.NETWORK_SNIFFING': 'MacroAttackStage.PRIVLEDGE_ESC', 'MicroAttackStage.BRUTE_FORCE_CREDS': 'MacroAttackStage.PRIVLEDGE_ESC', 'MicroAttackStage.ACCT_MANIP': 'MacroAttackStage.PRIVLEDGE_ESC', 'MicroAttackStage.TRUSTED_ORG_EXP': 'MacroAttackStage.TARGETED_EXP', 'MicroAttackStage.PUBLIC_APP_EXP': 'MacroAttackStage.TARGETED_EXP', 'MicroAttackStage.REMOTE_SERVICE_EXP': 'MacroAttackStage.TARGETED_EXP', 'MicroAttackStage.SPEARPHISHING': 'MacroAttackStage.TARGETED_EXP', 'MicroAttackStage.SERVICE_SPECIFIC': 'MacroAttackStage.TARGETED_EXP', 'MicroAttackStage.ARBITRARY_CODE_EXE': 'MacroAttackStage.TARGETED_EXP', 'MicroAttackStage.DEFENSE_EVASION': 'MacroAttackStage.ENSURE_ACCESS', 'MicroAttackStage.COMMAND_AND_CONTROL': 'MacroAttackStage.ENSURE_ACCESS', 'MicroAttackStage.LATERAL_MOVEMENT': 'MacroAttackStage.ENSURE_ACCESS', 'MicroAttackStage.END_POINT_DOS': 'MacroAttackStage.DISRUPT', 'MicroAttackStage.NETWORK_DOS': 'MacroAttackStage.DISRUPT', 'MicroAttackStage.SERVICE_STOP': 'MacroAttackStage.DISRUPT', 'MicroAttackStage.RESOURCE_HIJACKING': 'MacroAttackStage.DISRUPT', 'MicroAttackStage.DATA_DESTRUCTION': 'MacroAttackStage.DISTROY', 'MicroAttackStage.CONTENT_WIPE': 'MacroAttackStage.DISTROY', 'MicroAttackStage.DATA_ENCRYPTION': 'MacroAttackStage.DISTORT', 'MicroAttackStage.DEFACEMENT': 'MacroAttackStage.DISTORT', 'MicroAttackStage.DATA_MANIPULATION': 'MacroAttackStage.DISTORT', 'MicroAttackStage.DATA_EXFILTRATION': 'MacroAttackStage.DISCLOSURE', 'MicroAttackStage.DATA_DELIVERY': 'MacroAttackStage.DELIVERY', 'MicroAttackStage.NON_MALICIOUS': 'MacroAttackStage.NONE', 'MicroAttackStage.PRIV_ESC': 'MacroAttackStage.PRIVLEDGE_ESC'}
mcols = list(set([(0.8941176470588236, 0.10196078431372549, 0.10980392156862745), (0.21568627450980393, 0.49411764705882355, 0.7215686274509804), (0.30196078431372547, 0.6862745098039216, 0.2901960784313726), (0.596078431372549, 0.3058823529411765, 0.6392156862745098), (1.0, 0.4980392156862745, 0.0), (0.6509803921568628, 0.33725490196078434, 0.1568627450980392), (0.9686274509803922, 0.5058823529411764, 0.7490196078431373), (0.6, 0.6, 0.6), (0.4, 0.7607843137254902, 0.6470588235294118), (0.9882352941176471, 0.5529411764705883, 0.3843137254901961), (0.5529411764705883, 0.6274509803921569, 0.796078431372549), (0.9058823529411765, 0.5411764705882353, 0.7647058823529411), (0.6509803921568628, 0.8470588235294118, 0.32941176470588235), (1.0, 0.8509803921568627, 0.1843137254901961), (0.8980392156862745, 0.7686274509803922, 0.5803921568627451), (0.7019607843137254, 0.7019607843137254, 0.7019607843137254), (0.12156862745098039, 0.4666666666666667, 0.7058823529411765), (1.0, 0.4980392156862745, 0.054901960784313725), (0.17254901960784313, 0.6274509803921569, 0.17254901960784313), (0.8392156862745098, 0.15294117647058825, 0.1568627450980392), (0.5803921568627451, 0.403921568627451, 0.7411764705882353), (0.5490196078431373, 0.33725490196078434, 0.29411764705882354), (0.8901960784313725, 0.4666666666666667, 0.7607843137254902), (0.4980392156862745, 0.4980392156862745, 0.4980392156862745), (0.7372549019607844, 0.7411764705882353, 0.13333333333333333), (0.09019607843137255, 0.7450980392156863, 0.8117647058823529), (0.10588235294117647, 0.6196078431372549, 0.4666666666666667), (0.8509803921568627, 0.37254901960784315, 0.00784313725490196), (0.4588235294117647, 0.4392156862745098, 0.7019607843137254), (0.9058823529411765, 0.1607843137254902, 0.5411764705882353), (0.4, 0.6509803921568628, 0.11764705882352941), (0.9019607843137255, 0.6705882352941176, 0.00784313725490196), (0.6509803921568628, 0.4627450980392157, 0.11372549019607843), (0.4, 0.4, 0.4), (0.4980392156862745, 0.788235294117647, 0.4980392156862745), (0.7450980392156863, 0.6823529411764706, 0.8313725490196079), (0.9921568627450981, 0.7529411764705882, 0.5254901960784314), (0.2196078431372549, 0.4235294117647059, 0.6901960784313725), (0.9411764705882353, 0.00784313725490196, 0.4980392156862745), (0.7490196078431373, 0.3568627450980392, 0.09019607843137253), (0.4, 0.4, 0.4), (0.984313725490196, 0.7058823529411765, 0.6823529411764706), (0.7019607843137254, 0.803921568627451, 0.8901960784313725), (0.8, 0.9215686274509803, 0.7725490196078432), (0.8705882352941177, 0.796078431372549, 0.8941176470588236), (0.996078431372549, 0.8509803921568627, 0.6509803921568628), (0.8980392156862745, 0.8470588235294118, 0.7411764705882353), (0.9921568627450981, 0.8549019607843137, 0.9254901960784314)]))
small_mapping = {
    1:'tarID',
    2:'surf', 
    4:'hostD',
    5: 'serD',
    6: 'vulnD', 
    7: 'infoD',
    10:'uPrivEsc',
    11:'rPrivEsc',
    12:'netSniff',
    13:'bfCred',
    14:'acctManip',
    15:'TOexp',
    16:'PAexp',
    17:'remoteexp',
    18:'sPhish',
    19:'servS',
    20:'evasion',
    21:'CnC',
    22:'lateral',
    23:'ACE',
    99:'privEsc',
    100:'endDOS',
    101:'netDOS',
    102:'serStop',
    103:'resHJ',
    104:'dDestruct',
    105:'cWipe',
    106:'dEncrypt',
    107:'deface',
    108:'dManip',
    109:'exfil',
    110:'delivery',
    111: 'phish',
    999: 'benign'
}
rev_smallmapping = dict([(value, key) for key, value in small_mapping.items()]) 

## DO NOT EXECUTE: Convert each alert into Moskal categoru: Manual mapping
ccdc_combined = { "ET CHAT IRC authorization message": MicroAttackStage.NON_MALICIOUS,
    "ET POLICY Cisco Device in Config Mode": MicroAttackStage.SERVICE_SPECIFIC,
    "ET POLICY Cisco Device New Config Built": MicroAttackStage.SERVICE_SPECIFIC,
    "ET SCAN Behavioral Unusual Port 445 traffic Potential Scan or Infection": MicroAttackStage.SERVICE_DISC,
    "ET SCAN Behavioral Unusual Port 139 traffic Potential Scan or Infection": MicroAttackStage.SERVICE_DISC,
    "ET SCAN Behavioral Unusual Port 137 traffic Potential Scan or Infection": MicroAttackStage.SERVICE_DISC,
    "ET SCAN Behavioral Unusual Port 135 traffic Potential Scan or Infection": MicroAttackStage.SERVICE_DISC,
    "ET SCAN Behavioral Unusual Port 1434 traffic Potential Scan or Infection": MicroAttackStage.SERVICE_DISC,
    "ET SCAN Behavioral Unusual Port 1433 traffic Potential Scan or Infection": MicroAttackStage.SERVICE_DISC,
    "ET CHAT IRC USER command": MicroAttackStage.NON_MALICIOUS,
    "ET CHAT IRC NICK command": MicroAttackStage.NON_MALICIOUS,
    "ET CHAT IRC JOIN command": MicroAttackStage.NON_MALICIOUS,
    "ET CHAT IRC PRIVMSG command": MicroAttackStage.NON_MALICIOUS,
    "ET CHAT Google Talk (Jabber) Client Login": MicroAttackStage.INFO_DISC,
    "ET CHAT Google IM traffic Jabber client sign-on": MicroAttackStage.INFO_DISC,
    "ET SCAN Potential SSH Scan OUTBOUND": MicroAttackStage.DATA_EXFILTRATION,
    "ET POLICY Outgoing Basic Auth Base64 HTTP Password detected unencrypted": MicroAttackStage.PRIV_ESC,
    "ET MALWARE Suspicious User-Agent (1 space)": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET TFTP Outbound TFTP Error Message": MicroAttackStage.DATA_EXFILTRATION,
    "ET P2P BitTorrent DHT ping request": MicroAttackStage.DATA_DELIVERY,
    "ET P2P BitTorrent DHT nodes reply": MicroAttackStage.DATA_DELIVERY,
    "ET P2P BitTorrent DHT announce_peers request": MicroAttackStage.DATA_DELIVERY,
    "ET POLICY IP Check Domain (whatismyip in HTTP Host)": MicroAttackStage.INFO_DISC,
    "ET POLICY TeamViewer Dyngate User-Agent": MicroAttackStage.INFO_DISC,
    "ET SCAN Non-Allowed Host Tried to Connect to MySQL Server": MicroAttackStage.INFO_DISC,
    "ET POLICY User-Agent (Launcher)": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET POLICY PDF With Embedded File": MicroAttackStage.DATA_DELIVERY,
    "ET P2P Bittorrent P2P Client User-Agent (Transmission/1.x)": MicroAttackStage.DATA_DELIVERY,
    "ET WEB_CLIENT Hex Obfuscation of String.fromCharCode % Encoding": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET WEB_CLIENT Hex Obfuscation of charCodeAt % Encoding": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET WEB_CLIENT Hex Obfuscation of document.write % Encoding": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET WEB_CLIENT Hex Obfuscation of Script Tag % Encoding": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET WEB_CLIENT Hex Obfuscation of unescape % Encoding": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET WEB_CLIENT Hex Obfuscation of substr % Encoding": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET POLICY DNS Query For XXX Adult Site Top Level Domain": MicroAttackStage.NON_MALICIOUS,
    "ET POLICY Dropbox Client Broadcasting": MicroAttackStage.DATA_EXFILTRATION,
    "ET POLICY Cleartext WordPress Login": MicroAttackStage.PRIV_ESC,
    "ET POLICY Http Client Body contains passwd= in cleartext": MicroAttackStage.PRIV_ESC,
    "ET POLICY Http Client Body contains pass= in cleartext": MicroAttackStage.PRIV_ESC,
    "ET POLICY Http Client Body contains pwd= in cleartext": MicroAttackStage.PRIV_ESC,
    "ET POLICY curl User-Agent Outbound": MicroAttackStage.DATA_DELIVERY,
    "ET POLICY libwww-perl User-Agent": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET POLICY Python-urllib/ Suspicious User Agent": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET SCAN Nessus FTP Scan detected (ftp_anonymous.nasl)": MicroAttackStage.INFO_DISC,
    "ET POLICY GNU/Linux APT User-Agent Outbound likely related to package management": MicroAttackStage.NON_MALICIOUS,
    "ET POLICY GNU/Linux YUM User-Agent Outbound likely related to package management": MicroAttackStage.NON_MALICIOUS,
    "ET TROJAN Suspicious User-Agent (WindowsNT) With No Separating Space": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET POLICY HTTP traffic on port 443 (POST)": MicroAttackStage.NON_MALICIOUS,
    "ET POLICY Vulnerable Java Version 1.7.x Detected": MicroAttackStage.NON_MALICIOUS,
    "ET POLICY Outdated Flash Version M1": MicroAttackStage.NON_MALICIOUS,
    "ET POLICY OpenVPN Update Check": MicroAttackStage.NON_MALICIOUS,
    "ET POLICY DynDNS CheckIp External IP Address Server Response": MicroAttackStage.INFO_DISC,
    #"ET POLICY DNS Query for TOR Hidden Domain .onion Accessible Via TOR": MicroAttackStage.DEFENSE_EVASION,
    #"ET POLICY TOR .exit Pseudo TLD DNS Query": MicroAttackStage.DEFENSE_EVASION,
    "ET SNMP Attempt to retrieve Cisco Config via TFTP (CISCO-CONFIG-COPY)": MicroAttackStage.INFO_DISC,
    "ET WEB_SERVER ColdFusion componentutils access": MicroAttackStage.DATA_EXFILTRATION,
    "ET WEB_SERVER ColdFusion administrator access": MicroAttackStage.PRIV_ESC,
    "ET DNS Query to a *.pw domain - Likely Hostile": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET ATTACK_RESPONSE Net User Command Response": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET DOS Possible NTP DDoS Inbound Frequent Un-Authed MON_LIST Requests IMPL 0x03": MicroAttackStage.NETWORK_DOS,
    "ET WORM TheMoon.linksys.router 1": MicroAttackStage.NETWORK_DOS,
    "ET POLICY Application Crash Report Sent to Microsoft": MicroAttackStage.NON_MALICIOUS,
    "ET CURRENT_EVENTS Malformed HeartBeat Request": MicroAttackStage.VULN_DISC,
    "ET CURRENT_EVENTS Malformed HeartBeat Response": MicroAttackStage.VULN_DISC,
    "ET CURRENT_EVENTS Possible OpenSSL HeartBleed Large HeartBeat Response (Client Init Vuln Server)": MicroAttackStage.PRIV_ESC,
    "ET CURRENT_EVENTS Possible OpenSSL HeartBleed Large HeartBeat Response (Server Init Vuln Client)": MicroAttackStage.PRIV_ESC,
    "ET CURRENT_EVENTS Possible TLS HeartBleed Unencrypted Request Method 4 (Inbound to Common SSL Port)": MicroAttackStage.PRIV_ESC,
    "ET CURRENT_EVENTS Possible TLS HeartBleed Unencrypted Request Method 3 (Inbound to Common SSL Port)": MicroAttackStage.PRIV_ESC,
    "ET TROJAN HTTP Executable Download from suspicious domain with direct request/fake browser (multiple families) ": MicroAttackStage.DATA_DELIVERY,
    #"ET POLICY TLS possible TOR SSL traffic": MicroAttackStage.DEFENSE_EVASION,
    "ET POLICY PE EXE or DLL Windows file download HTTP": MicroAttackStage.DATA_DELIVERY,
    "ET EXPLOIT Metasploit Random Base CharCode JS Encoded String": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET DOS Possible SSDP Amplification Scan in Progress": MicroAttackStage.NETWORK_DOS,
    "ET WEB_SERVER Possible CVE-2014-6271 Attempt in Headers": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP Version Number": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP Cookie": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET EXPLOIT Possible Pure-FTPd CVE-2014-6271 attempt": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET POLICY SSLv3 inbound connection to server vulnerable to POODLE attack": MicroAttackStage.NON_MALICIOUS,
    "ET POLICY Possible IP Check api.ipify.org": MicroAttackStage.INFO_DISC,
    "ET CURRENT_EVENTS Terse alphanumeric executable downloader high likelihood of being hostile": MicroAttackStage.DATA_DELIVERY,
    "ET POLICY Metasploit Framework Checking For Update": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET POLICY Dropbox DNS Lookup - Possible Offsite File Backup in Use": MicroAttackStage.DATA_EXFILTRATION,
    "ET WEB_SERVER Possible IIS Integer Overflow DoS (CVE-2015-1635)": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET USER_AGENTS MSF Meterpreter Default User Agent": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET ATTACK_RESPONSE Metasploit Meterpreter Reverse HTTPS certificate": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET WEB_SERVER Possible CVE-2014-6271 Attempt": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET EXPLOIT Serialized Java Object Calling Common Collection Function": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET POLICY Possible HTA Application Download": MicroAttackStage.DATA_DELIVERY,
    "ET CURRENT_EVENTS SUSPICIOUS Firesale gTLD EXE DL with no Referer June 13 2016": MicroAttackStage.DATA_DELIVERY,
    "ET POLICY Possible Kali Linux hostname in DHCP Request Packet": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET WEB_CLIENT HTA File containing Wscript.Shell Call - Potential CVE-2017-0199": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET SCAN Possible Nmap User-Agent Observed": MicroAttackStage.HOST_DISC,
    "ET POLICY Outdated Flash Version M2": MicroAttackStage.NON_MALICIOUS,
    #"ET CURRENT_EVENTS Possible AMSI Powershell Bypass Attempt B642": MicroAttackStage.DEFENSE_EVASION,
    "ET WEB_CLIENT PowerShell call in script 1": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET WEB_CLIENT PowerShell call in script 2": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET EXPLOIT Cisco Smart Install Exploitation Tool - ChangeConfig": MicroAttackStage.SERVICE_SPECIFIC,
    "ET EXPLOIT Cisco Smart Install Exploitation Tool - GetConfig": MicroAttackStage.SERVICE_SPECIFIC,
    "ET POLICY SMB Executable File Transfer": MicroAttackStage.DATA_EXFILTRATION,
    "ET POLICY SMB2 NT Create AndX Request For an Executable File": MicroAttackStage.DATA_DELIVERY,
    "ET POLICY SMB2 NT Create AndX Request For a Powershell .ps1 File": MicroAttackStage.DATA_DELIVERY,
    "ET POLICY SMB2 NT Create AndX Request For a .bat File": MicroAttackStage.DATA_DELIVERY,
    "ET POLICY SMB2 NT Create AndX Request For a DLL File - Possible Lateral Movement": MicroAttackStage.DATA_DELIVERY,
    "ET POLICY SMB2 Remote AT Scheduled Job Create Request": MicroAttackStage.DATA_EXFILTRATION,
    "ET POLICY SMB Remote AT Scheduled Job Pipe Creation": MicroAttackStage.DATA_EXFILTRATION,
    "ET POLICY Powershell Activity Over SMB - Likely Lateral Movement": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET POLICY Powershell Command With Hidden Window Argument Over SMB - Likely Lateral Movement": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET POLICY Powershell Command With No Profile Argument Over SMB - Likely Lateral Movement": MicroAttackStage.COMMAND_AND_CONTROL,
    "GPL CHAT Jabber/Google Talk Outgoing Traffic": MicroAttackStage.INFO_DISC,
    "GPL CHAT Google Talk Logon": MicroAttackStage.NON_MALICIOUS,
    "GPL ATTACK_RESPONSE id check returned root": MicroAttackStage.PRIV_ESC,
    "GPL CHAT Google Talk Startup": MicroAttackStage.NON_MALICIOUS,
    "SURICATA SMTP invalid reply": MicroAttackStage.NON_MALICIOUS,
    "SURICATA SMTP invalid pipelined sequence": MicroAttackStage.NON_MALICIOUS,
    "SURICATA SMTP no server welcome message": MicroAttackStage.NON_MALICIOUS,
    "SURICATA SMTP tls rejected": MicroAttackStage.NON_MALICIOUS,
    "SURICATA SMTP data command rejected": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP gzip decompression failed": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP request field missing colon": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP invalid request chunk len": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP invalid response chunk len": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP invalid transfer encoding value in request": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP invalid content length field in request": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP status 100-Continue already seen": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP unable to match response to request": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP request header invalid": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP missing Host header": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP Host header ambiguous": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP invalid response field folding": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP response field missing colon": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP response header invalid": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP multipart generic error": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP Host part of URI is invalid": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP Host header invalid": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP METHOD terminated by non-compliant character": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP Request abnormal Content-Encoding header": MicroAttackStage.NON_MALICIOUS,
    "SURICATA TLS invalid record type": MicroAttackStage.NON_MALICIOUS,
    "SURICATA TLS invalid handshake message": MicroAttackStage.NON_MALICIOUS,
    "SURICATA TLS invalid certificate": MicroAttackStage.NON_MALICIOUS,
    "SURICATA TLS certificate invalid length": MicroAttackStage.NON_MALICIOUS,
    "SURICATA TLS error message encountered": MicroAttackStage.NON_MALICIOUS,
    "SURICATA TLS invalid record/traffic": MicroAttackStage.NON_MALICIOUS,
    "SURICATA TLS overflow heartbeat encountered, possible exploit attempt (heartbleed)": MicroAttackStage.NON_MALICIOUS,
    "SURICATA TLS invalid record version": MicroAttackStage.NON_MALICIOUS,
    "SURICATA TLS invalid SNI length": MicroAttackStage.NON_MALICIOUS,
    "SURICATA TLS handshake invalid length": MicroAttackStage.NON_MALICIOUS,
    "SURICATA DNS Unsolicited response": MicroAttackStage.NON_MALICIOUS,
    "SURICATA DNS malformed response data": MicroAttackStage.NON_MALICIOUS,
    "SURICATA DNS Not a response": MicroAttackStage.NON_MALICIOUS,
    "ET CINS Active Threat Intelligence Poor Reputation IP group 44": MicroAttackStage.INFO_DISC,
    "ET CNC Ransomware Tracker Reported CnC Server group 101": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET COMPROMISED Known Compromised or Hostile Host Traffic group 9": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 128": MicroAttackStage.NON_MALICIOUS,
    "ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 155": MicroAttackStage.NON_MALICIOUS,
    "ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 271": MicroAttackStage.NON_MALICIOUS,
    "ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 285": MicroAttackStage.NON_MALICIOUS,
    "ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 328": MicroAttackStage.NON_MALICIOUS,
    "ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 519": MicroAttackStage.NON_MALICIOUS,
    "ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 595": MicroAttackStage.NON_MALICIOUS,
    "ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 615": MicroAttackStage.NON_MALICIOUS,
    "ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 684": MicroAttackStage.NON_MALICIOUS,
    
    
    
    "ET SCAN Potential SSH Scan": MicroAttackStage.SERVICE_DISC,
    "ET CHAT Skype VOIP Checking Version (Startup)": MicroAttackStage.NON_MALICIOUS,
    "ET TROJAN HackerDefender Root Kit Remote Connection Attempt Detected": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET CHAT Skype User-Agent detected": MicroAttackStage.NON_MALICIOUS,
    "ET SCAN Nessus User Agent": MicroAttackStage.VULN_DISC,
    "ET POLICY POSSIBLE Web Crawl using Wget": MicroAttackStage.INFO_DISC,
    "ET P2P Edonkey Publicize File ACK": MicroAttackStage.DATA_DELIVERY,
    "ET SCAN PHP Attack Tool Morfeus F Scanner": MicroAttackStage.VULN_DISC,
    "ET POLICY Incoming Basic Auth Base64 HTTP Password detected unencrypted": MicroAttackStage.PRIV_ESC,
    "ET WEB_SERVER Possible SQL Injection Attempt SELECT FROM": MicroAttackStage.DATA_MANIPULATION,
    "ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT": MicroAttackStage.DATA_MANIPULATION,
    "ET POLICY External Unencrypted Connection to BASE Console": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET WEB_SERVER cmd.exe In URI - Possible Command Execution Attempt": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET WEB_SERVER /system32/ in Uri - Possible Protected Directory Access Attempt": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET WEB_SERVER Script tag in URI Possible Cross Site Scripting Attempt": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET WEB_SERVER Onmouseover= in URI - Likely Cross Site Scripting Attempt": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET TROJAN Possible Windows executable sent when remote host claims to send html content": MicroAttackStage.DATA_DELIVERY,
    "ET POLICY Proxy TRACE Request - inbound": MicroAttackStage.INFO_DISC,
    "ET WEB_SERVER DFind w00tw00t GET-Requests": MicroAttackStage.VULN_DISC,
    "ET CHAT Facebook Chat using XMPP": MicroAttackStage.NON_MALICIOUS,
    "ET WEB_SERVER Exploit Suspected PHP Injection Attack (cmd=)": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET WEB_SERVER SELECT USER SQL Injection Attempt in URI": MicroAttackStage.PRIV_ESC,
    "ET WEB_SERVER Possible Attempt to Get SQL Server Version in URI using SELECT VERSION": MicroAttackStage.INFO_DISC,
    "ET WEB_SERVER MYSQL SELECT CONCAT SQL Injection Attempt": MicroAttackStage.DATA_MANIPULATION,
    "ET WEB_SERVER PHP Easteregg Information-Disclosure (phpinfo)": MicroAttackStage.INFO_DISC,
    "ET WEB_SERVER PHP Easteregg Information-Disclosure (php-logo)": MicroAttackStage.INFO_DISC,
    "ET WEB_SERVER PHP Easteregg Information-Disclosure (zend-logo)": MicroAttackStage.INFO_DISC,
    "ET POLICY User-Agent (NSIS_Inetc (Mozilla)) - Sometimes used by hostile installers": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET WEB_SERVER /bin/sh In URI Possible Shell Command Execution Attempt": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET WEB_SERVER PHP tags in HTTP POST": MicroAttackStage.DATA_DELIVERY,
    "ET WEB_CLIENT Hex Obfuscation of document.write % Encoding": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET WEB_SERVER Likely Malicious Request for /proc/self/environ": MicroAttackStage.INFO_DISC,
    "ET POLICY Dropbox.com Offsite File Backup in Use": MicroAttackStage.DATA_EXFILTRATION,
    "ET POLICY Dropbox Client Broadcasting": MicroAttackStage.DATA_EXFILTRATION,
    "ET POLICY HTTP Request to a *.tk domain": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET WEB_SERVER PHP Possible php Remote File Inclusion Attempt": MicroAttackStage.DATA_DELIVERY,
    "ET POLICY curl User-Agent Outbound": MicroAttackStage.DATA_DELIVERY,
    "ET POLICY Python-urllib/ Suspicious User Agent": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET WEB_SERVER Muieblackcat scanner": MicroAttackStage.VULN_DISC,
    "ET POLICY Executable served from Amazon S3": MicroAttackStage.DATA_DELIVERY,
    "ET SCAN Apache mod_deflate DoS via many multiple byte Range values": MicroAttackStage.NETWORK_DOS,
    "ET POLICY GNU/Linux APT User-Agent Outbound likely related to package management": MicroAttackStage.NON_MALICIOUS,
    "ET POLICY GNU/Linux YUM User-Agent Outbound likely related to package management": MicroAttackStage.NON_MALICIOUS,
    "ET TROJAN Double HTTP/1.1 Header Inbound - Likely Hostile Traffic": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET MALWARE W32/OpenCandy Adware Checkin": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET MALWARE Common Adware Library ISX User Agent Detected": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET DNS Query for .su TLD (Soviet Union) Often Malware Related": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET WEB_SERVER IIS 8.3 Filename With Wildcard (Possible File/Dir Bruteforce)": MicroAttackStage.DATA_EXFILTRATION,
    "ET TROJAN Unknown - Loader - Check .exe Updated": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET WEB_SERVER ColdFusion administrator access": MicroAttackStage.PRIV_ESC,
    "ET SCAN GET with HTML tag in start of URI seen with PHPMyAdmin scanning": MicroAttackStage.VULN_DISC,
    "ET WEB_SERVER WebShell Generic - wget http - POST": MicroAttackStage.DATA_DELIVERY,
    "ET DNS Query to a *.pw domain - Likely Hostile": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET WEB_SERVER allow_url_include PHP config option in uri": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET WEB_SERVER safe_mode PHP config option in uri": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET WEB_SERVER suhosin.simulation PHP config option in uri": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET WEB_SERVER disable_functions PHP config option in uri": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET WEB_SERVER open_basedir PHP config option in uri": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET WEB_SERVER auto_prepend_file PHP config option in uri": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET WEB_SERVER Access to /phppath/php Possible Plesk 0-day Exploit June 05 2013": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET WEB_SERVER PHP SERVER SuperGlobal in URI": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET SCAN NETWORK Incoming Masscan detected": MicroAttackStage.HOST_DISC,
    "ET CURRENT_EVENTS Possible Magnitude IE EK Payload Nov 8 2013": MicroAttackStage.DATA_DELIVERY,
    "ET WEB_SERVER Possible XXE SYSTEM ENTITY in POST BODY.": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET EXPLOIT Possible ZyXELs ZynOS Configuration Download Attempt (Contains Passwords)": MicroAttackStage.DATA_EXFILTRATION,
    "ET TROJAN Miuref/Boaxxe Checkin": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET POLICY PE EXE or DLL Windows file download HTTP": MicroAttackStage.DATA_DELIVERY,
    "ET WEB_SERVER Possible CVE-2014-6271 Attempt in Headers": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP Cookie": MicroAttackStage.ARBITRARY_CODE_EXE,
    #"ET ATTACK_RESPONSE Output of id command from HTTP server": MicroAttackStage.INIT,
    "ET WEB_SERVER Possible bash shell piped to dev tcp Inbound to WebServer": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET WEB_SERVER CURL Command Specifying Output in HTTP Headers": MicroAttackStage.DATA_DELIVERY,
    "ET WEB_SERVER WGET Command Specifying Output in HTTP Headers": MicroAttackStage.DATA_DELIVERY,
    "ET WEB_SERVER WGET Command Specifying Output in HTTP Headers": MicroAttackStage.DATA_DELIVERY,
    "ET POLICY SSLv3 outbound connection from client vulnerable to POODLE attack": MicroAttackStage.NON_MALICIOUS,
    "ET WEB_SERVER WEB-PHP phpinfo access": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET WEB_SERVER PHP.//Input in HTTP POST": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET WEB_SERVER PHP System Command in HTTP POST": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET POLICY Dropbox DNS Lookup - Possible Offsite File Backup in Use": MicroAttackStage.DATA_EXFILTRATION,
    "ET CURRENT_EVENTS Unknown Malicious Second Stage Download URI Struct M2 Feb 06 2015": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET CURRENT_EVENTS Nuclear EK Landing Apr 03 2015": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET CURRENT_EVENTS Nuclear EK Landing Apr 08 2015": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET CURRENT_EVENTS Nuclear EK Landing Apr 22 2015": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET TROJAN Poweliks Clickfraud CnC M4": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET CURRENT_EVENTS Unknown Malicious Second Stage Download URI Struct Sept 15 2015": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET WEB_SERVER Possible CVE-2014-6271 Attempt": MicroAttackStage.ARBITRARY_CODE_EXE,
    "ET POLICY Outdated Flash Version M2": MicroAttackStage.NON_MALICIOUS,
    "ET WEB_SERVER 401TRG Generic Webshell Request - POST with wget in body": MicroAttackStage.DATA_DELIVERY,
    "ET TROJAN Possible NanoCore C2 60B": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET TROJAN Possible Metasploit Payload Common Construct Bind_API (from server)": MicroAttackStage.COMMAND_AND_CONTROL,
    "GPL CHAT Jabber/Google Talk Outgoing Traffic": MicroAttackStage.NON_MALICIOUS,
    "GPL ATTACK_RESPONSE id check returned root": MicroAttackStage.PRIV_ESC,
    "GPL EXPLOIT .htr access": MicroAttackStage.INFO_DISC,
    "GPL WEB_SERVER iisadmin access": MicroAttackStage.INFO_DISC,
    "GPL EXPLOIT fpcount access": MicroAttackStage.ARBITRARY_CODE_EXE,
    "GPL WEB_SERVER global.asa access": MicroAttackStage.INFO_DISC,
    "GPL EXPLOIT iisadmpwd attempt": MicroAttackStage.INFO_DISC,
    "GPL WEB_SERVER Tomcat directory traversal attempt": MicroAttackStage.INFO_DISC,
    "GPL WEB_SERVER Tomcat server snoop access": MicroAttackStage.INFO_DISC,
    "GPL WEB_SERVER .htaccess access": MicroAttackStage.INFO_DISC,
    "GPL WEB_SERVER /~root access": MicroAttackStage.INFO_DISC,
    "GPL WEB_SERVER 403 Forbidden": MicroAttackStage.INFO_DISC,
    "GPL EXPLOIT ISAPI .ida access": MicroAttackStage.DATA_EXFILTRATION,
    "GPL EXPLOIT ISAPI .ida attempt": MicroAttackStage.DATA_EXFILTRATION,
    "GPL EXPLOIT ISAPI .idq attempt": MicroAttackStage.DATA_EXFILTRATION,
    "GPL EXPLOIT ISAPI .idq access": MicroAttackStage.DATA_EXFILTRATION,
    "GPL EXPLOIT CodeRed v2 root.exe access": MicroAttackStage.PRIV_ESC,
    "GPL EXPLOIT iissamples access": MicroAttackStage.INFO_DISC,
    "GPL WEB_SERVER viewcode access": MicroAttackStage.INFO_DISC,
    "GPL EXPLOIT /iisadmpwd/aexp2.htr access": MicroAttackStage.DATA_EXFILTRATION,
    "GPL WEB_SERVER Oracle Java Process Manager access": MicroAttackStage.INFO_DISC,
    "GPL WEB_SERVER printenv access": MicroAttackStage.INFO_DISC,
    "GPL WEB_SERVER perl post attempt": MicroAttackStage.ARBITRARY_CODE_EXE,
    "GPL WEB_SERVER Tomcat null byte directory listing attempt": MicroAttackStage.INFO_DISC,
    "GPL WEB_SERVER mod_gzip_status access": MicroAttackStage.INFO_DISC,
    "SURICATA HTTP gzip decompression failed": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP request field missing colon": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP invalid transfer encoding value in request": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP unable to match response to request": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP request header invalid": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP missing Host header": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP Host header ambiguous": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP response header invalid": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP Host part of URI is invalid": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP Host header invalid": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP URI terminated by non-compliant character": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP METHOD terminated by non-compliant character": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP Request line with leading whitespace": MicroAttackStage.NON_MALICIOUS,
    "SURICATA HTTP Request abnormal Content-Encoding header": MicroAttackStage.NON_MALICIOUS,
    "SURICATA TLS invalid handshake message": MicroAttackStage.NON_MALICIOUS,
    "SURICATA TLS invalid record/traffic": MicroAttackStage.NON_MALICIOUS,
    "SURICATA TLS invalid record version": MicroAttackStage.NON_MALICIOUS,
    "SURICATA DNS Unsolicited response": MicroAttackStage.NON_MALICIOUS,
    "ET CINS Active Threat Intelligence Poor Reputation IP group 66": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET CINS Active Threat Intelligence Poor Reputation IP group 91": MicroAttackStage.COMMAND_AND_CONTROL,
    "ET CINS Active Threat Intelligence Poor Reputation IP group 100": MicroAttackStage.COMMAND_AND_CONTROL,
    }
usual_mapping = {'ET ATTACK_RESPONSE Net User Command Response': MicroAttackStage.INFO_DISC,#
           'ET ATTACK_RESPONSE Possible /etc/passwd via HTTP (linux style)': MicroAttackStage.DATA_EXFILTRATION,#
           'ET ATTACK_RESPONSE Possible BeEF HTTP Headers Inbound': MicroAttackStage.COMMAND_AND_CONTROL,#
           'ET ATTACK_RESPONSE python shell spawn attempt': MicroAttackStage.COMMAND_AND_CONTROL, #
           'ET CURRENT_EVENTS Likely Linux/Xorddos DDoS Attack Participation (gggatat456.com)': MicroAttackStage.END_POINT_DOS,
           'ET CURRENT_EVENTS Likely Linux/Xorddos DDoS Attack Participation (xxxatat456.com)': MicroAttackStage.END_POINT_DOS,
           'ET CURRENT_EVENTS Malformed HeartBeat Request': MicroAttackStage.VULN_DISC,
           'ET CURRENT_EVENTS Possible TLS HeartBleed Unencrypted Request Method 3 (Inbound to Common SSL Port)': MicroAttackStage.DATA_EXFILTRATION,
           'ET CURRENT_EVENTS Possible ZyXELs ZynOS Configuration Download Attempt (Contains Passwords)': MicroAttackStage.DATA_EXFILTRATION,
           'ET CURRENT_EVENTS QNAP Shellshock CVE-2014-6271': MicroAttackStage.ARBITRARY_CODE_EXE,
           'ET CURRENT_EVENTS Terse alphanumeric executable downloader high likelihood of being hostile': MicroAttackStage.DATA_DELIVERY, #
           'ET DNS Query for .su TLD (Soviet Union) Often Malware Related': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET DNS Query to a .tk domain - Likely Hostile': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET DOS Microsoft Remote Desktop (RDP) Syn then Reset 30 Second DoS Attempt': MicroAttackStage.NETWORK_DOS,
           'ET DOS Possible NTP DDoS Inbound Frequent Un-Authed MON_LIST Requests IMPL 0x03': MicroAttackStage.NETWORK_DOS,
           'ET DOS Possible SSDP Amplification Scan in Progress': MicroAttackStage.NETWORK_DOS,
           'ET EXPLOIT Possible GoldenPac Priv Esc in-use': MicroAttackStage.USER_PRIV_ESC,
           'ET EXPLOIT Possible Postfix CVE-2014-6271 attempt': MicroAttackStage.ARBITRARY_CODE_EXE,
           'ET EXPLOIT Possible Pure-FTPd CVE-2014-6271 attempt': MicroAttackStage.ARBITRARY_CODE_EXE,
           'ET EXPLOIT Possible SpamAssassin Milter Plugin Remote Arbitrary Command Injection Attempt': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET EXPLOIT REDIS Attempted SSH Key Upload': MicroAttackStage.USER_PRIV_ESC,
           'ET FTP Suspicious Quotation Mark Usage in FTP Username': MicroAttackStage.ACCT_MANIP,
           'ET INFO Executable Download from dotted-quad Host': MicroAttackStage.COMMAND_AND_CONTROL, #Do we need a malware injection stage?
           'ET INFO Possible Windows executable sent when remote host claims to send a Text File': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET INFO WinHttp AutoProxy Request wpad.dat Possible BadTunnel': MicroAttackStage.DATA_EXFILTRATION, #This is more "man in the middle"
           'ET MOBILE_MALWARE Android/Code4hk.A Checkin': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET P2P TOR 1.0 Outbound Circuit Traffic': MicroAttackStage.DEFENSE_EVASION,
           'ET POLICY DNS Update From External net': MicroAttackStage.DATA_MANIPULATION,
           'ET POLICY Executable and linking format (ELF) file download': MicroAttackStage.COMMAND_AND_CONTROL, #will need to be checked out
           'ET POLICY Executable and linking format (ELF) file download Over HTTP': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET POLICY Http Client Body contains pass= in cleartext': MicroAttackStage.PRIV_ESC,  #Once again, check this out.
           'ET POLICY Incoming Basic Auth Base64 HTTP Password detected unencrypted': MicroAttackStage.USER_PRIV_ESC ,
           'ET POLICY MS Remote Desktop Administrator Login Request': MicroAttackStage.ROOT_PRIV_ESC,
           'ET POLICY MS Terminal Server Root login': MicroAttackStage.ROOT_PRIV_ESC,
           'ET POLICY Outgoing Basic Auth Base64 HTTP Password detected unencrypted': MicroAttackStage.USER_PRIV_ESC, #outgoing vs. incoming?
           'ET POLICY PE EXE or DLL Windows file download HTTP': MicroAttackStage.DATA_DELIVERY,
           'ET POLICY Python-urllib/ Suspicious User Agent': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET POLICY RDP connection confirm': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET POLICY Suspicious inbound to MSSQL port 1433': MicroAttackStage.VULN_DISC,
           'ET POLICY Suspicious inbound to Oracle SQL port 1521': MicroAttackStage.VULN_DISC,
           'ET POLICY Suspicious inbound to PostgreSQL port 5432': MicroAttackStage.VULN_DISC,
           'ET POLICY Suspicious inbound to mSQL port 4333': MicroAttackStage.VULN_DISC,
           'ET POLICY Suspicious inbound to mySQL port 3306': MicroAttackStage.VULN_DISC,
           'ET POLICY curl User-Agent Outbound': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET SCAN Apache mod_deflate DoS via many multiple byte Range values': MicroAttackStage.NETWORK_DOS,
           'ET SCAN Behavioral Unusual Port 135 traffic Potential Scan or Infection': MicroAttackStage.SERVICE_DISC,
           'ET SCAN Behavioral Unusual Port 139 traffic Potential Scan or Infection': MicroAttackStage.SERVICE_DISC,
           'ET SCAN Behavioral Unusual Port 1433 traffic Potential Scan or Infection': MicroAttackStage.SERVICE_DISC,
           'ET SCAN Behavioral Unusual Port 1434 traffic Potential Scan or Infection': MicroAttackStage.SERVICE_DISC,
           'ET SCAN Behavioral Unusual Port 445 traffic Potential Scan or Infection': MicroAttackStage.SERVICE_DISC,
           'ET SCAN Behavioral Unusually fast Terminal Server Traffic Potential Scan or Infection (Inbound)': MicroAttackStage.HOST_DISC,
           'ET SCAN DEBUG Method Request with Command': MicroAttackStage.PUBLIC_APP_EXP,
           'ET SCAN DirBuster Scan in Progress': MicroAttackStage.VULN_DISC, #This is typically trying to see what directories are avabilable
           'ET SCAN DirBuster Web App Scan in Progress': MicroAttackStage.VULN_DISC,
           'ET SCAN Hydra User-Agent': MicroAttackStage.BRUTE_FORCE_CREDS,
           'ET SCAN LibSSH Based Frequent SSH Connections Likely BruteForce Attack': MicroAttackStage.BRUTE_FORCE_CREDS,
           'ET SCAN Multiple MySQL Login Failures Possible Brute Force Attempt': MicroAttackStage.BRUTE_FORCE_CREDS ,
           'ET SCAN NMAP OS Detection Probe': MicroAttackStage.SERVICE_DISC,
           'ET SCAN NMAP SIP Version Detect OPTIONS Scan': MicroAttackStage.VULN_DISC,
           'ET SCAN Nessus FTP Scan detected (ftp_anonymous.nasl)': MicroAttackStage.SERVICE_DISC,
           'ET SCAN Nessus FTP Scan detected (ftp_writeable_directories.nasl)': MicroAttackStage.SERVICE_DISC,
           'ET SCAN Nessus User Agent': MicroAttackStage.VULN_DISC,
           'ET SCAN Nikto Web App Scan in Progress': MicroAttackStage.VULN_DISC,
           'ET SCAN Nmap NSE Heartbleed Request': MicroAttackStage.VULN_DISC,
           'ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap Scripting Engine)': MicroAttackStage.HOST_DISC,
           'ET SCAN OpenVAS User-Agent Inbound': MicroAttackStage.VULN_DISC,
           'ET SCAN Possible Nmap User-Agent Observed': MicroAttackStage.HOST_DISC,
           'ET SCAN Potential FTP Brute-Force attempt response': MicroAttackStage.BRUTE_FORCE_CREDS,
           'ET SCAN Potential SSH Scan': MicroAttackStage.SERVICE_DISC,
           'ET SCAN Potential VNC Scan 5800-5820': MicroAttackStage.SERVICE_DISC,
           'ET SCAN Potential VNC Scan 5900-5920': MicroAttackStage.SERVICE_DISC,
           'ET SCAN Rapid IMAP Connections - Possible Brute Force Attack': MicroAttackStage.BRUTE_FORCE_CREDS,
           'ET SCAN Rapid IMAPS Connections - Possible Brute Force Attack': MicroAttackStage.BRUTE_FORCE_CREDS,
           'ET SCAN Rapid POP3 Connections - Possible Brute Force Attack': MicroAttackStage.BRUTE_FORCE_CREDS,
           'ET SCAN Rapid POP3S Connections - Possible Brute Force Attack': MicroAttackStage.BRUTE_FORCE_CREDS,
           'ET SCAN Redis SSH Key Overwrite Probing': MicroAttackStage.USER_PRIV_ESC,
           'ET SNMP Attempted UDP Access Attempt to Cisco IOS 12.1 Hidden Read/Write Community String ILMI': MicroAttackStage.REMOTE_SERVICE_EXP,
           'ET SNMP Samsung Printer SNMP Hardcode RW Community String': MicroAttackStage.REMOTE_SERVICE_EXP,
           'ET SNMP missing community string attempt 1': MicroAttackStage.REMOTE_SERVICE_EXP,
           'ET TROJAN ATTACKER IRCBot - PRIVMSG Response - Directory Listing': MicroAttackStage.DATA_EXFILTRATION,
           'ET TROJAN ATTACKER IRCBot - PRIVMSG Response - Directory Listing *nix': MicroAttackStage.DATA_EXFILTRATION,
           'ET TROJAN ATTACKER IRCBot - PRIVMSG Response - ipconfig command output': MicroAttackStage.DATA_EXFILTRATION,
           'ET TROJAN ATTACKER IRCBot - PRIVMSG Response - net command output': MicroAttackStage.DATA_EXFILTRATION,
           'ET TROJAN ATTACKER IRCBot - The command completed successfully - PRIVMSG Response': MicroAttackStage.DATA_EXFILTRATION,
           'ET TROJAN DDoS.XOR Checkin': MicroAttackStage.NETWORK_DOS, #may also be network sniffing
           'ET TROJAN NgrBot IRC CnC Channel Join': MicroAttackStage.COMMAND_AND_CONTROL, ##
           'ET TROJAN Windows WMIC COMPUTERSYSTEM get Microsoft Windows DOS prompt command exit OUTBOUND': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET TROJAN Windows WMIC NETLOGIN get Microsoft Windows DOS prompt command exit OUTBOUND': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET TROJAN Windows WMIC NIC get Microsoft Windows DOS prompt command exit OUTBOUND': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET TROJAN Windows WMIC OS get Microsoft Windows DOS prompt command exit OUTBOUND': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET TROJAN Windows WMIC PROCESS get Microsoft Windows DOS prompt command exit OUTBOUND': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET TROJAN Windows WMIC SERVER get Microsoft Windows DOS prompt command exit OUTBOUND': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET TROJAN Windows WMIC SERVICE get Microsoft Windows DOS prompt command exit OUTBOUND': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET TROJAN Windows WMIC SHARE get Microsoft Windows DOS prompt command exit OUTBOUND': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET TROJAN Windows WMIC STARTUP get Microsoft Windows DOS prompt command exit OUTBOUND': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET TROJAN Windows dir Microsoft Windows DOS prompt command exit OUTBOUND': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET TROJAN Windows driverquery -si Microsoft Windows DOS prompt command exit OUTBOUND': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET TROJAN Windows driverquery -v Microsoft Windows DOS prompt command exit OUTBOUND': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET TROJAN Windows gpresult Microsoft Windows DOS prompt command exit OUTBOUND': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET TROJAN Windows nbtstat -a Microsoft Windows DOS prompt command exit OUTBOUND': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET TROJAN Windows nbtstat -n Microsoft Windows DOS prompt command exit OUTBOUND': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET TROJAN Windows nbtstat -r Microsoft Windows DOS prompt command exit OUTBOUND': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET TROJAN Windows nbtstat -s Microsoft Windows DOS prompt command exit OUTBOUND': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET TROJAN Windows netstat Microsoft Windows DOS prompt command exit OUTBOUND': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET TROJAN Windows quser Microsoft Windows DOS prompt command exit OUTBOUND': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET TROJAN Windows qwinsta Microsoft Windows DOS prompt command exit OUTBOUND': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET WEB_CLIENT BeEF Cookie Outbound': MicroAttackStage.SERVICE_SPECIFIC,
           'ET WEB_SERVER DD-WRT Information Disclosure Attempt': MicroAttackStage.DATA_EXFILTRATION,
           'ET WEB_SERVER HTTP 414 Request URI Too Large': MicroAttackStage.COMMAND_AND_CONTROL, #This is if the URL is too long AKA command injection
           'ET WEB_SERVER PHP Possible file Remote File Inclusion Attempt': MicroAttackStage.DATA_DELIVERY,
           'ET WEB_SERVER PHP Possible https Local File Inclusion Attempt': MicroAttackStage.DATA_DELIVERY,
           'ET WEB_SERVER PHP Possible php Remote File Inclusion Attempt': MicroAttackStage.DATA_DELIVERY,
           'ET WEB_SERVER PHP tags in HTTP POST': MicroAttackStage.DATA_DELIVERY,
           'ET WEB_SERVER Possible CVE-2014-3120 Elastic Search Remote Code Execution Attempt': MicroAttackStage.ARBITRARY_CODE_EXE,
           'ET WEB_SERVER Possible CVE-2015-1427 Elastic Search Sandbox Escape Remote Code Execution Attempt': MicroAttackStage.ARBITRARY_CODE_EXE,
           'ET WEB_SERVER Possible MySQL SQLi Attempt Information Schema Access': MicroAttackStage.DATA_EXFILTRATION,
           'ET WEB_SERVER Possible SQL Injection (exec)': MicroAttackStage.COMMAND_AND_CONTROL,
           'ET WEB_SERVER Tilde in URI - potential .inc source disclosure vulnerability': MicroAttackStage.DATA_EXFILTRATION,
           'ET WEB_SERVER Tilde in URI - potential .php~ source disclosure vulnerability': MicroAttackStage.DATA_EXFILTRATION,
           'ET WEB_SERVER WEB-PHP phpinfo access': MicroAttackStage.SURFING, #Changed from exfiltration
           'ET WEB_SPECIFIC_APPS PHP-CGI query string parameter vulnerability': MicroAttackStage.DATA_EXFILTRATION,
           'GPL ATTACK_RESPONSE id check returned root': MicroAttackStage.ROOT_PRIV_ESC,
           'GPL DNS named authors attempt': MicroAttackStage.INFO_DISC,
           'GPL DNS named version attempt': MicroAttackStage.INFO_DISC,
           'GPL FTP .forward': MicroAttackStage.INFO_DISC,
           'GPL FTP CWD ...': MicroAttackStage.INFO_DISC,
           'GPL FTP CWD .... attempt': MicroAttackStage.INFO_DISC,
           'GPL FTP CWD Root directory transversal attempt': MicroAttackStage.INFO_DISC,
           'GPL FTP CWD ~ attempt': MicroAttackStage.INFO_DISC,
           'GPL FTP CWD ~root attempt': MicroAttackStage.INFO_DISC,
           'GPL FTP LIST directory traversal attempt': MicroAttackStage.INFO_DISC,
           'GPL FTP MKD overflow': MicroAttackStage.INFO_DISC,
           'GPL FTP MKD overflow attempt': MicroAttackStage.INFO_DISC,
           'GPL FTP PORT bounce attempt': MicroAttackStage.INFO_DISC,
           'GPL FTP SITE EXEC attempt': MicroAttackStage.INFO_DISC,
           'GPL ICMP_INFO PING *NIX': MicroAttackStage.SERVICE_DISC,
           'GPL ICMP_INFO PING BSDtype': MicroAttackStage.SERVICE_DISC,
           'GPL MISC UPnP malformed advertisement': MicroAttackStage.ARBITRARY_CODE_EXE,
           'GPL MISC rsh root': MicroAttackStage.ROOT_PRIV_ESC,
           'GPL NETBIOS DCERPC IActivation little endian bind attempt': MicroAttackStage.ARBITRARY_CODE_EXE,
           'GPL NETBIOS DCERPC Remote Activation bind attempt': MicroAttackStage.ARBITRARY_CODE_EXE,
           'GPL NETBIOS SMB-DS ADMIN$ share access': MicroAttackStage.DATA_EXFILTRATION,
           'GPL NETBIOS SMB-DS C$ share access': MicroAttackStage.DATA_EXFILTRATION,
           'GPL NETBIOS SMB-DS C$ unicode share access': MicroAttackStage.DATA_EXFILTRATION,
           'GPL NETBIOS SMB-DS D$ share access': MicroAttackStage.DATA_EXFILTRATION,
           'GPL NETBIOS SMB-DS IPC$ share access': MicroAttackStage.DATA_EXFILTRATION,
           'GPL NETBIOS SMB-DS IPC$ unicode share access': MicroAttackStage.DATA_EXFILTRATION,
           'GPL NETBIOS SMB-DS Session Setup NTMLSSP asn1 overflow attempt': MicroAttackStage.ARBITRARY_CODE_EXE,
           'GPL NETBIOS SMB-DS Session Setup NTMLSSP unicode asn1 overflow attempt': MicroAttackStage.ARBITRARY_CODE_EXE,
           'GPL NETBIOS SMB-DS repeated logon failure': MicroAttackStage.BRUTE_FORCE_CREDS,
           'GPL POLICY Sun JavaServer default password login attempt': MicroAttackStage.BRUTE_FORCE_CREDS,
           'GPL POP3 POP3 PASS overflow attempt': MicroAttackStage.ARBITRARY_CODE_EXE,
           'GPL RPC portmap bootparam request TCP': MicroAttackStage.SERVICE_DISC ,
           'GPL RPC portmap cachefsd request TCP': MicroAttackStage.ARBITRARY_CODE_EXE,
           'GPL RPC portmap listing TCP 111': MicroAttackStage.SERVICE_DISC,
           'GPL RPC portmap listing UDP 111': MicroAttackStage.SERVICE_DISC,
           'GPL RPC portmap mountd request UDP': MicroAttackStage.SERVICE_DISC,
           'GPL RPC portmap rstatd request TCP': MicroAttackStage.SERVICE_DISC,
           'GPL RPC portmap rusers request TCP': MicroAttackStage.SERVICE_DISC,
           'GPL RPC portmap sadmind request TCP': MicroAttackStage.SERVICE_DISC,
           'GPL RPC portmap ypserv request TCP': MicroAttackStage.SERVICE_DISC,
           'GPL RPC portmap ypupdated request TCP': MicroAttackStage.ARBITRARY_CODE_EXE,
           'GPL RPC xdmcp info query': MicroAttackStage.INFO_DISC,
           'GPL SNMP private access udp': MicroAttackStage.ACCT_MANIP, #check this out, this is a bit unclear
           'GPL SNMP public access udp': MicroAttackStage.ACCT_MANIP,
           'GPL WEB_SERVER globals.pl access': MicroAttackStage.INFO_DISC, #Changed from exfiltration
           'GPL WEB_SERVER mod_gzip_status access': MicroAttackStage.INFO_DISC,#Changed from exfiltration
           'GPL WEB_SERVER perl post attempt': MicroAttackStage.DATA_DELIVERY,
          'ET ATTACK_RESPONSE Output of id command from HTTP server': MicroAttackStage.INFO_DISC,  #********  CPTC 2018 STARTS HERE **********
          'ET CHAT MSN status change': MicroAttackStage.DATA_MANIPULATION,
          'ET CURRENT_EVENTS Possible TLS HeartBleed Unencrypted Request Method 4 (Inbound to Common SSL Port)': MicroAttackStage.VULN_DISC,
          'ET EXPLOIT Exim/Dovecot Possible MAIL FROM Command Execution': MicroAttackStage.COMMAND_AND_CONTROL,
          'ET EXPLOIT Possible CVE-2014-3704 Drupal SQLi attempt URLENCODE 1': MicroAttackStage.COMMAND_AND_CONTROL,
          'ET EXPLOIT Possible ZyXELs ZynOS Configuration Download Attempt (Contains Passwords)': MicroAttackStage.DATA_EXFILTRATION,
          'ET INFO NetSSH SSH Version String Hardcoded in Metasploit': MicroAttackStage.INFO_DISC,
          'ET INFO SUSPICIOUS Dotted Quad Host MZ Response': MicroAttackStage.DATA_EXFILTRATION,
          'ET INFO Windows OS Submitting USB Metadata to Microsoft': MicroAttackStage.INFO_DISC,
          'ET P2P BitTorrent peer sync': MicroAttackStage.DATA_EXFILTRATION,
          'ET POLICY GNU/Linux APT User-Agent Outbound likely related to package management': MicroAttackStage.NON_MALICIOUS,
          'ET POLICY Http Client Body contains passwd= in cleartext': MicroAttackStage.INFO_DISC,
          'ET POLICY IP Check Domain (icanhazip. com in HTTP Host)': MicroAttackStage.INFO_DISC,
          'ET POLICY Outbound MSSQL Connection to Non-Standard Port - Likely Malware': MicroAttackStage.DATA_EXFILTRATION,
          'ET POLICY POSSIBLE Web Crawl using Curl': MicroAttackStage.INFO_DISC,
          'ET POLICY POSSIBLE Web Crawl using Wget': MicroAttackStage.INFO_DISC,
          'ET POLICY Powershell Activity Over SMB - Likely Lateral Movement': MicroAttackStage.LATERAL_MOVEMENT,
          'ET POLICY Powershell Command With Hidden Window Argument Over SMB - Likely Lateral Movement': MicroAttackStage.LATERAL_MOVEMENT,
          'ET POLICY Powershell Command With No Profile Argument Over SMB - Likely Lateral Movement': MicroAttackStage.LATERAL_MOVEMENT,
          'ET POLICY Powershell Command With NonInteractive Argument Over SMB - Likely Lateral Movement': MicroAttackStage.LATERAL_MOVEMENT,
          'ET POLICY Proxy TRACE Request - inbound': MicroAttackStage.INFO_DISC,
          'ET POLICY SMB2 NT Create AndX Request For a .bat File': MicroAttackStage.LATERAL_MOVEMENT,
          'ET POLICY SMB2 NT Create AndX Request For an Executable File': MicroAttackStage.LATERAL_MOVEMENT,
          'ET SCAN Apache mod_proxy Reverse Proxy Exposure 1': MicroAttackStage.PUBLIC_APP_EXP,
          'ET SCAN Grendel-Scan Web Application Security Scan Detected': MicroAttackStage.VULN_DISC,
          'ET SCAN NMAP SIP Version Detection Script Activity': MicroAttackStage.SERVICE_DISC,
          'ET SCAN NMAP SQL Spider Scan': MicroAttackStage.VULN_DISC,
          'ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap NSE)': MicroAttackStage.VULN_DISC,
          'ET SCAN Potential SSH Scan OUTBOUND': MicroAttackStage.DATA_EXFILTRATION,
          'ET SCAN SFTP/FTP Password Exposure via sftp-config.json': MicroAttackStage.INFO_DISC,
          'ET SCAN Sqlmap SQL Injection Scan': MicroAttackStage.VULN_DISC,
          'ET SCAN Suspicious inbound to MSSQL port 1433': MicroAttackStage.VULN_DISC,
          'ET SCAN Suspicious inbound to Oracle SQL port 1521': MicroAttackStage.VULN_DISC,
          'ET SCAN Suspicious inbound to PostgreSQL port 5432': MicroAttackStage.VULN_DISC,
          'ET SCAN Suspicious inbound to mSQL port 4333': MicroAttackStage.VULN_DISC,
          'ET SCAN Suspicious inbound to mySQL port 3306': MicroAttackStage.VULN_DISC,
          'ET TROJAN Backdoor family PCRat/Gh0st CnC traffic (OUTBOUND) 106': MicroAttackStage.COMMAND_AND_CONTROL,
          'ET TROJAN Possible Metasploit Payload Common Construct Bind_API (from server)': MicroAttackStage.COMMAND_AND_CONTROL,
          'ET TROJAN Possible NanoCore C2 64B': MicroAttackStage.COMMAND_AND_CONTROL,
          'ET TROJAN Possible Zendran ELF IRCBot Joining Channel 2': MicroAttackStage.COMMAND_AND_CONTROL,
          'ET USER_AGENTS Go HTTP Client User-Agent': MicroAttackStage.INFO_DISC,
          'ET WEB_SERVER /bin/bash In URI, Possible Shell Command Execution Attempt Within Web Exploit': MicroAttackStage.COMMAND_AND_CONTROL,
          'ET WEB_SERVER /bin/sh In URI Possible Shell Command Execution Attempt': MicroAttackStage.COMMAND_AND_CONTROL,
          'ET WEB_SERVER /etc/shadow Detected in URI': MicroAttackStage.DATA_EXFILTRATION,
          'ET WEB_SERVER /system32/ in Uri - Possible Protected Directory Access Attempt': MicroAttackStage.DATA_EXFILTRATION,
          'ET WEB_SERVER Access to /phppath/php Possible Plesk 0-day Exploit June 05 2013': MicroAttackStage.SERVICE_SPECIFIC,
          'ET WEB_SERVER Attempt To Access MSSQL xp_cmdshell Stored Procedure Via URI': MicroAttackStage.ROOT_PRIV_ESC,  #May not be the case
          'ET WEB_SERVER CRLF Injection - Newline Characters in URL': MicroAttackStage.PUBLIC_APP_EXP,
          'ET WEB_SERVER ColdFusion adminapi access': MicroAttackStage.COMMAND_AND_CONTROL,
          'ET WEB_SERVER ColdFusion administrator access': MicroAttackStage.ROOT_PRIV_ESC,
          'ET WEB_SERVER ColdFusion componentutils access': MicroAttackStage.DATA_EXFILTRATION,
          'ET WEB_SERVER ColdFusion password.properties access': MicroAttackStage.DATA_EXFILTRATION,
          'ET WEB_SERVER Coldfusion cfcexplorer Directory Traversal': MicroAttackStage.DATA_EXFILTRATION,
          'ET WEB_SERVER Exploit Suspected PHP Injection Attack (cmd=)': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SERVER IIS 8.3 Filename With Wildcard (Possible File/Dir Bruteforce)': MicroAttackStage.DATA_EXFILTRATION,
          'ET WEB_SERVER Joomla Component SQLi Attempt': MicroAttackStage.DATA_EXFILTRATION,
          'ET WEB_SERVER MYSQL SELECT CONCAT SQL Injection Attempt': MicroAttackStage.DATA_MANIPULATION,
          'ET WEB_SERVER Onmouseover= in URI - Likely Cross Site Scripting Attempt': MicroAttackStage.TRUSTED_ORG_EXP,
          'ET WEB_SERVER PHP ENV SuperGlobal in URI': MicroAttackStage.INFO_DISC,
          'ET WEB_SERVER PHP Easteregg Information-Disclosure (funny-logo)': MicroAttackStage.INFO_DISC,
          'ET WEB_SERVER PHP Easteregg Information-Disclosure (php-logo)': MicroAttackStage.INFO_DISC,
          'ET WEB_SERVER PHP Easteregg Information-Disclosure (phpinfo)': MicroAttackStage.INFO_DISC,
          'ET WEB_SERVER PHP Easteregg Information-Disclosure (zend-logo)': MicroAttackStage.INFO_DISC,
          'ET WEB_SERVER PHP REQUEST SuperGlobal in URI': MicroAttackStage.INFO_DISC,
          'ET WEB_SERVER PHP SERVER SuperGlobal in URI': MicroAttackStage.INFO_DISC,
          'ET WEB_SERVER PHP SESSION SuperGlobal in URI': MicroAttackStage.INFO_DISC,
          'ET WEB_SERVER PHP System Command in HTTP POST': MicroAttackStage.COMMAND_AND_CONTROL,
          'ET WEB_SERVER PHP.//Input in HTTP POST': MicroAttackStage.INFO_DISC, #may be more than this
          'ET WEB_SERVER Possible Attempt to Get SQL Server Version in URI using SELECT VERSION': MicroAttackStage.INFO_DISC,
          'ET WEB_SERVER Possible CVE-2013-0156 Ruby On Rails XML YAML tag with !ruby': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SERVER Possible CVE-2014-6271 Attempt': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP Cookie': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP Version Number': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SERVER Possible CVE-2014-6271 Attempt in Headers': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SERVER Possible Cherokee Web Server GET AUX Request Denial Of Service Attempt': MicroAttackStage.NETWORK_DOS,
          'ET WEB_SERVER Possible IIS Integer Overflow DoS (CVE-2015-1635)': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SERVER Possible SQL Injection Attempt SELECT FROM': MicroAttackStage.DATA_MANIPULATION,
          'ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT': MicroAttackStage.DATA_MANIPULATION,
          'ET WEB_SERVER Possible SQLi xp_cmdshell POST body': MicroAttackStage.ROOT_PRIV_ESC,
          'ET WEB_SERVER Possible XXE SYSTEM ENTITY in POST BODY.': MicroAttackStage.DATA_EXFILTRATION,
          'ET WEB_SERVER Possible bash shell piped to dev tcp Inbound to WebServer': MicroAttackStage.COMMAND_AND_CONTROL,
          'ET WEB_SERVER SELECT USER SQL Injection Attempt in URI': MicroAttackStage.ACCT_MANIP,
          'ET WEB_SERVER SQL Injection Local File Access Attempt Using LOAD_FILE': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SERVER Script tag in URI Possible Cross Site Scripting Attempt': MicroAttackStage.REMOTE_SERVICE_EXP,
          'ET WEB_SERVER Suspicious Chmod Usage in URI': MicroAttackStage.DATA_MANIPULATION,
          'ET WEB_SERVER allow_url_include PHP config option in uri': MicroAttackStage.PUBLIC_APP_EXP,
          'ET WEB_SERVER auto_prepend_file PHP config option in uri': MicroAttackStage.PUBLIC_APP_EXP,
          'ET WEB_SERVER cmd.exe In URI - Possible Command Execution Attempt': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SERVER disable_functions PHP config option in uri': MicroAttackStage.PUBLIC_APP_EXP,
          'ET WEB_SERVER open_basedir PHP config option in uri': MicroAttackStage.PUBLIC_APP_EXP,
          'ET WEB_SERVER safe_mode PHP config option in uri': MicroAttackStage.PUBLIC_APP_EXP,
          'ET WEB_SERVER suhosin.simulation PHP config option in uri': MicroAttackStage.PUBLIC_APP_EXP,
          'ET WEB_SPECIFIC_APPS Achievo debugger.php config_atkroot parameter Remote File Inclusion Attempt': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS AjaxPortal ajaxp_backend.php page Parameter SQL Injection': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS AjaxPortal di.php pathtoserverdata Parameter Remote File Inclusion Attempt': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS AlstraSoft AskMe que_id Parameter SELECT FROM SQL Injection Attempt': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS BASE base_stat_common.php remote file include': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS BLOG CMS nsextt parameter Cross Site Scripting Vulnerability': MicroAttackStage.TRUSTED_ORG_EXP,
          'ET WEB_SPECIFIC_APPS BaconMap updatelist.php filepath Local File Inclusion Attempt': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS Beerwins PHPLinkAdmin edlink.php linkid Parameter SQL Injection': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS Community CMS view.php article_id Parameter SQL Injection': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS CultBooking lang parameter Local File Inclusion Attempt': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS Demium CMS urheber.php name Parameter Local File Inclusion': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS DesktopOnNet don3_requiem.php app_path Parameter Remote File Inclusion': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS DesktopOnNet frontpage.php app_path Parameter Remote File Inclusion': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS Enthusiast path parameter Remote File Inclusion': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS Fork-CMS js.php module parameter Local File Inclusion Attempt': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS FormMailer formmailer.admin.inc.php BASE_DIR Parameter Remote File Inclusion Attempt': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS Golem Gaming Portal root_path Parameter Remote File inclusion Attempt': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS Horde type Parameter Local File Inclusion Attempt': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS IBSng str Parameter Cross Site Scripting Attempt': MicroAttackStage.PUBLIC_APP_EXP,
          'ET WEB_SPECIFIC_APPS JobHut browse.php pk Parameter SQL Injection': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS Joomla 3.7.0 - Sql Injection (CVE-2017-8917)': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS Joomla AjaxChat Component ajcuser.php GLOBALS Parameter Remote File Inclusion Attempt': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS Joomla Dada Mail Manager Component config.dadamail.php GLOBALS Parameter Remote File Inclusion': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS Joomla Onguma Time Sheet Component onguma.class.php mosConfig_absolute_path Parameter Remote File Inclusion': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS Joomla Simple RSS Reader admin.rssreader.php mosConfig_live_site Parameter Remote File Inclusion': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS Joomla swMenuPro ImageManager.php Remote File Inclusion Attempt': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS KR-Web krgourl.php DOCUMENT_ROOT Parameter Remote File Inclusion Attempt': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS KingCMS menu.php CONFIG Parameter Remote File Inclusion': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS MAXcms fm_includes_special Parameter Remote File Inclusion Attempt': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS MODx CMS snippet.reflect.php reflect_base Remote File Inclusion': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS Mambo Component com_smf smf.php Remote File Inclusion Attempt': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS Microhard Systems 3G/4G Cellular Ethernet and Serial Gateway - Default Credentials': MicroAttackStage.USER_PRIV_ESC,
          'ET WEB_SPECIFIC_APPS Noname Media Photo Galerie Standard SQL Injection Attempt -- view.php id SELECT': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS OBOphiX fonctions_racine.php chemin_lib parameter Remote File Inclusion Attempt': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS OpenX phpAdsNew phpAds_geoPlugin Parameter Remote File Inclusion Attempt': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS Opencadastre soustab.php script Local File Inclusion Vulnerability': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS Oracle JSF2 Path Traversal Attempt': MicroAttackStage.INFO_DISC,
          'ET WEB_SPECIFIC_APPS OrangeHRM path Parameter Local File Inclusion Attempt': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS PHP Aardvark Topsites PHP CONFIG PATH Remote File Include Attempt': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS PHP Booking Calendar page_info_message parameter Cross-Site Scripting Vulnerability ': MicroAttackStage.TRUSTED_ORG_EXP,
          'ET WEB_SPECIFIC_APPS PHP Classifieds class.phpmailer.php lang_path Parameter Remote File Inclusion Attempt': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS PHP phpMyAgenda rootagenda Remote File Include Attempt': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS PHP-Paid4Mail RFI attempt ': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS PHPOF DB_AdoDB.Class.PHP PHPOF_INCLUDE_PATH parameter Remote File Inclusion': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS PithCMS oldnews_reader.php lang Parameter Local File Inclusion Attempt': MicroAttackStage.DATA_EXFILTRATION, #This is local files only
          'ET WEB_SPECIFIC_APPS Plone and Zope cmd Parameter Remote Command Execution Attempt': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS PointComma pctemplate.php pcConfig Parameter Remote File Inclusion Attempt': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS Possible JBoss JMX Console Beanshell Deployer WAR Upload and Deployment Exploit Attempt': MicroAttackStage.COMMAND_AND_CONTROL,
          'ET WEB_SPECIFIC_APPS Possible Mambo/Joomla! com_koesubmit Component \'koesubmit.php\' Remote File Inclusion Attempt': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS Possible OpenSiteAdmin pageHeader.php Remote File Inclusion Attempt': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS Possible eFront database.php Remote File Inclusion Attempt': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS PozScripts Business Directory Script cid parameter SQL Injection': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS ProdLer prodler.class.php sPath Parameter Remote File Inclusion Attempt': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS ProjectButler RFI attempt ': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS Request to Wordpress W3TC Plug-in dbcache Directory': MicroAttackStage.INFO_DISC,
          'ET WEB_SPECIFIC_APPS SAPID get_infochannel.inc.php Remote File inclusion Attempt': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS SERWeb load_lang.php configdir Parameter Remote File Inclusion': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS SERWeb main_prepend.php functionsdir Parameter Remote File Inclusion': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS SFS EZ Hotscripts-like Site showcategory.php cid Parameter SQL Injection': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS SFS EZ Hotscripts-like Site software-description.php id Parameter SQL Injection': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS Sisplet CMS komentar.php site_path Parameter Remote File Inclusion Attempt': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS TECHNOTE shop_this_skin_path Parameter Remote File Inclusion': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS Turnkeyforms Software Directory showcategory.php cid parameter SQL Injection': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS Ve-EDIT edit_htmlarea.php highlighter Parameter Remote File Inclusion': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS Vulnerable Magento Adminhtml Access': MicroAttackStage.ROOT_PRIV_ESC,
          'ET WEB_SPECIFIC_APPS WEB-PHP RCE PHPBB 2004-1315': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ET WEB_SPECIFIC_APPS WHMCompleteSolution templatefile Parameter Local File Inclusion Attempt': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS WikyBlog which Parameter Cross Site Scripting Attempt': MicroAttackStage.TRUSTED_ORG_EXP,
          'ET WEB_SPECIFIC_APPS YapBB class_yapbbcooker.php cfgIncludeDirectory Parameter Remote File Inclusion': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS Zen Cart loader_file Parameter Local File Inclusion Attempt': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS axdcms aXconf Parameter Local File Inclusion Attempt': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS evision cms addplain.php module parameter Local File Inclusion': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS p-Table for WordPress wptable-tinymce.php ABSPATH Parameter RFI Attempt': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS phPortal gunaysoft.php icerikyolu Parameter Remote File Inclusion': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS phPortal gunaysoft.php sayfaid Parameter Remote File Inclusion': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS phpSkelSite theme parameter remote file inclusion': MicroAttackStage.DATA_DELIVERY,
          'ET WEB_SPECIFIC_APPS phptraverse mp3_id.php GLOBALS Parameter Remote File Inclusion Attempt': MicroAttackStage.DATA_DELIVERY,
          'ETPRO ATTACK_RESPONSE MongoDB Database Enumeration Request': MicroAttackStage.DATA_EXFILTRATION,
          'ETPRO ATTACK_RESPONSE MongoDB Version Request': MicroAttackStage.INFO_DISC,
          'ETPRO EXPLOIT SOAP Netgear WNDR Auth Bypass/Info Disclosure': MicroAttackStage.ROOT_PRIV_ESC,
          'ETPRO SCAN IPMI Get Authentication Request (null seq number - null sessionID)': MicroAttackStage.HOST_DISC,
          'ETPRO TROJAN Likely Bot Nick in IRC ([country|so_version|computername])': MicroAttackStage.DATA_MANIPULATION,
          'ETPRO TROJAN Likely Bot Nick in Off Port IRC': MicroAttackStage.DATA_MANIPULATION,
          'ETPRO TROJAN Win32/Meterpreter Receiving Meterpreter M1': MicroAttackStage.COMMAND_AND_CONTROL,
          'ETPRO WEB_SERVER JexBoss Common URI struct Observed 2 (INBOUND)': MicroAttackStage.COMMAND_AND_CONTROL,
          'ETPRO WEB_SERVER Possible Information Leak Vuln CVE-2015-1648': MicroAttackStage.DATA_EXFILTRATION,
          'ETPRO WEB_SERVER SQLMap Scan Tool User Agent': MicroAttackStage.VULN_DISC,
          'ETPRO WEB_SPECIFIC_APPS CM Download Manager WP Plugin Code Injection': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ETPRO WEB_SPECIFIC_APPS Majordomo Directory Traversal Attempt': MicroAttackStage.INFO_DISC,
          'ETPRO WEB_SPECIFIC_APPS PHPMoAdmin RCE Attempt': MicroAttackStage.ARBITRARY_CODE_EXE,
          'ETPRO WEB_SPECIFIC_APPS ipTIME firmware < 9.58 RCE': MicroAttackStage.ROOT_PRIV_ESC,
          'GPL ATTACK_RESPONSE directory listing': MicroAttackStage.INFO_DISC,
          'GPL EXPLOIT .cnf access': MicroAttackStage.INFO_DISC, #Changed from exfiltration
          'GPL EXPLOIT .htr access': MicroAttackStage.INFO_DISC, #Changed from exfiltration
          'GPL EXPLOIT /iisadmpwd/aexp2.htr access': MicroAttackStage.ACCT_MANIP,
          'GPL EXPLOIT /msadc/samples/ access': MicroAttackStage.DATA_EXFILTRATION,
          'GPL EXPLOIT CodeRed v2 root.exe access': MicroAttackStage.ROOT_PRIV_ESC,
          'GPL EXPLOIT ISAPI .ida access': MicroAttackStage.DATA_EXFILTRATION,
          'GPL EXPLOIT ISAPI .idq access': MicroAttackStage.DATA_EXFILTRATION,
          'GPL EXPLOIT ISAPI .idq attempt': MicroAttackStage.INFO_DISC,
          'GPL EXPLOIT administrators.pwd access': MicroAttackStage.ROOT_PRIV_ESC,
          'GPL EXPLOIT fpcount access': MicroAttackStage.INFO_DISC,
          'GPL EXPLOIT iisadmpwd attempt': MicroAttackStage.INFO_DISC,
          'GPL EXPLOIT iissamples access': MicroAttackStage.INFO_DISC,
          'GPL EXPLOIT unicode directory traversal attempt': MicroAttackStage.INFO_DISC,
          'GPL POLICY PCAnywhere server response': MicroAttackStage.SERVICE_DISC,
          'GPL SMTP expn root': MicroAttackStage.ROOT_PRIV_ESC,
          'GPL SMTP vrfy root': MicroAttackStage.ROOT_PRIV_ESC,
          'GPL WEB_SERVER .htaccess access': MicroAttackStage.INFO_DISC, #Changed from exfiltration
          'GPL WEB_SERVER .htpasswd access': MicroAttackStage.INFO_DISC, #Changed from exfiltration
          'GPL WEB_SERVER /~root access': MicroAttackStage.INFO_DISC, #Changed from exfiltration
          'GPL WEB_SERVER 403 Forbidden': MicroAttackStage.INFO_DISC,
          'GPL WEB_SERVER DELETE attempt': MicroAttackStage.DATA_DESTRUCTION,
          'GPL WEB_SERVER Oracle Java Process Manager access': MicroAttackStage.RESOURCE_HIJACKING,
          'GPL WEB_SERVER Tomcat server snoop access': MicroAttackStage.DATA_EXFILTRATION,
          'GPL WEB_SERVER author.exe access': MicroAttackStage.INFO_DISC,
          'GPL WEB_SERVER authors.pwd access': MicroAttackStage.INFO_DISC,
          'GPL WEB_SERVER global.asa access': MicroAttackStage.INFO_DISC, #Changed from exfiltration
          'GPL WEB_SERVER iisadmin access': MicroAttackStage.INFO_DISC,#Changed from exfiltration
          'GPL WEB_SERVER printenv access': MicroAttackStage.INFO_DISC,#Changed from exfiltration
          'GPL WEB_SERVER python access attempt': MicroAttackStage.COMMAND_AND_CONTROL,
          'GPL WEB_SERVER service.cnf access': MicroAttackStage.INFO_DISC,#Changed from exfiltration
          'GPL WEB_SERVER service.pwd': MicroAttackStage.INFO_DISC,
          'GPL WEB_SERVER services.cnf access': MicroAttackStage.INFO_DISC,
          'GPL WEB_SERVER viewcode access': MicroAttackStage.INFO_DISC,
          'GPL WEB_SERVER writeto.cnf access': MicroAttackStage.INFO_DISC,
          'ETPRO EXPLOIT Possible Wget Arbitrary File Write Exploit Attempt (CVE-2016-4971)' : MicroAttackStage.DATA_DELIVERY,
           "INDICATOR-SCAN PHP backdoor scan attempt": MicroAttackStage.VULN_DISC,
           "MALWARE-CNC Win.Trojan.Dorkbot variant outbound connection" : MicroAttackStage.COMMAND_AND_CONTROL,
           "MALWARE-CNC Win.Trojan.Saeeka variant outbound connection" : MicroAttackStage.COMMAND_AND_CONTROL,
           "MALWARE-CNC Hacker-Tool sars notifier variant outbound connection php notification" : MicroAttackStage.COMMAND_AND_CONTROL,
           "MALWARE-CNC Win.Trojan.Alureon.DG runtime traffic detected" : MicroAttackStage.COMMAND_AND_CONTROL,
           "MALWARE-CNC TT-bot botnet variant outbound connection" : MicroAttackStage.COMMAND_AND_CONTROL,
           "ETPRO TROJAN CoinMiner Known Malicious Stratum Authline": MicroAttackStage.RESOURCE_HIJACKING,
           }
endpointDoS_signatures = [
    "ET DOS Excessive SMTP MAIL-FROM DDoS",
    "ET DOS Possible MYSQL GeomFromWKB() function Denial Of Service Attempt",
    "ET DOS Possible MYSQL SELECT WHERE to User Variable Denial Of Service Attempt"
    "ET DOS Possible MySQL ALTER DATABASE Denial Of Service Attempt",
    "ET DOS Possible SolarWinds TFTP Server Read Request Denial Of Service Attempt",
    "ET DOS SolarWinds TFTP Server Long Write Request Denial Of Service Attempt",
    "ETPRO DOS CA eTrust Intrusion Detection Encryption Key Handling Denial of Service",
    "ETPRO DOS Malformed Email Header Concatination Denial Of Service",
    "ET DOS IBM DB2 kuddb2 Remote Denial of Service Attempt",
    "ET DOS Possible Microsoft SQL Server Remote Denial Of Service Attempt",
    "ETPRO DOS iCal improper resource liberation",
    "ETPRO DOS iCal Null pointer de-reference Count Variable",
    "ETPRO DOS Linux Kernel NetFilter SCTP Unknown Chunk Types Denial of Service 1",
    "ETPRO DOS IBM DB2 Database Server Invalid Data Stream Denial of Service (Published Exploit)",
    "ETPRO DOS Firebird SQL op_connect_request Denial of Service",
    "ET DOS IBM Tivoli Endpoint Buffer Overflow Attempt",
    "ET DOS Microsoft Remote Desktop (RDP) Syn then Reset 30 Second DoS Attempt",
    "ET DOS Microsoft Remote Desktop Protocol (RDP) maxChannelIds Integer indef DoS Attempt",
    "ET DOS Microsoft Remote Desktop Protocol (RDP) maxChannelIds Negative Integer indef DoS Attempt",
    "ET DOS FreeBSD NFS RPC Kernel Panic",
    "ET DOS Trojan.BlackRev V1.Botnet HTTP Login POST Flood Traffic Inbound",
    "ET DOS Possible SSDP Amplification Scan in Progress",
    "ET DOS Outbound Low Orbit Ion Cannon LOIC Tool Internal User May Be Participating in DDOS",
    "ETPRO DOS Possible XMLRPC DoS in Progress",
    "ET DOS HTTP GET AAAAAAAA Likely FireFlood",
    "ET DOS MC-SQLR Response Outbound Possible DDoS Participation",
    "ET DOS Microsoft Windows LSASS Remote Memory Corruption (CVE-2017-0004)",
    "ET DOS Possible SMBLoris NBSS Length Mem Exhaustion Vuln Inbound",
    "ET DOS SMBLoris NBSS Length Mem Exhaustion Attempt (PoC Based)",
    "ET EXPLOIT FortiOS SSL VPN - Pre-Auth Messages Payload Buffer Overflow (CVE-2018-13381)"
]

networkDoS_signatures = [
    "ET DOS DNS BIND 9 Dynamic Update DoS attempt",
    "ET DOS Possible Cisco ASA 5500 Series Adaptive Security Appliance Remote SIP Inspection Device Reload Denial of Service Attempt",
    "ET DOS Catalyst memory leak attack",
    "ET DOS Microsoft Streaming Server Malformed Request",
    "ET DOS Potential Inbound NTP denial-of-service attempt (repeated mode 7 request)",
    "ET DOS Potential Inbound NTP denial-of-service attempt (repeated mode 7 reply)",
    "ET DOS Possible VNC ClientCutText Message Denial of Service/Memory Corruption Attempt",
    "ETPRO DOS Oracle Internet Directory Pre-Authentication LDAP Denial of Service Attempt",
    "ET DOS ntop Basic-Auth DOS inbound",
    "ET DOS ntop Basic-Auth DOS outbound",
    "ETPRO DOS Squid Proxy String Processing NULL Pointer Dereference Vulnerability",
    "ET DOS Cisco 514 UDP flood DoS",
    "ETPRO DOS Microsoft Windows Active Directory LDAP SearchRequest Denial of Service Attempt 1",
    "ET DOS ICMP Path MTU lowered below acceptable threshold",
    "ET DOS NetrWkstaUserEnum Request with large Preferred Max Len",
    "ETPRO DOS OpenLDAP Modrdn RDN NULL String Denial of Service Attempt",
    "ETPRO DOS Multiple Vendor ICMP Source Quench Denial of Service",
    "ETPRO DOS ISC DHCP Server Zero Length Client ID Denial of Service",
    "ETPRO DOS Microsoft Windows SMTP Service MX Record Denial Of Service",
    "ETPRO DOS FreeRADIUS RADIUS Server rad_decode Remote Denial of Service",
    "ETPRO DOS Squid Proxy FTP URI Processing Denial of Service",
    "ETPRO DOS Microsoft Host Integration Server snabase.exe Infinite Loop Denial of Service (Exploit Specific)",
    "ETPRO DOS Win32/Whybo.F DDoS Traffic Outbound",
    "ETPRO DOS Microsoft Windows NAT Helper DNS Query Denial of Service",
    "ETPRO DOS Microsoft Host Integration Server snabase.exe Denial of Service 1",
    "ET DOS Cisco Router HTTP DoS",
    "ET DOS Netgear DG632 Web Management Denial Of Service Attempt",
    "ET DOS Cisco 4200 Wireless Lan Controller Long Authorisation Denial of Service Attempt",
    "ETPRO DOS OpenLDAP ber_get_next BER Decoding Denial of Service Attempt",
    "ET DOS Microsoft Windows 7 ICMPv6 Router Advertisement Flood",
    "GPL DOS IGMP dos attack",
    "ET DOS LibuPnP CVE-2012-5963 ST UDN Buffer Overflow",
    "ET DOS Miniupnpd M-SEARCH Buffer Overflow CVE-2013-0229",
    "ETPRO DOS ICMP with truncated IPv6 header CVE-2013-3182",
    "ET DOS Possible NTP DDoS Inbound Frequent Un-Authed MON_LIST Requests IMPL 0x02",
    "ET DOS HOIC with booster inbound",
    "ET DOS Likely NTP DDoS In Progress PEER_LIST_SUM Response to Non-Ephemeral Port IMPL 0x02",
    "ETPRO DOS MS RADIUS DoS Vulnerability CVE-2015-0015",
    "ETPRO DOS Possible mDNS Amplification Scan in Progress",
    "ET DOS Potential Tsunami SYN Flood Denial Of Service Attempt",
    "ET DOS DNS Amplification Attack Possible Outbound Windows Non-Recursive Root Hint Reserved Port",
    "ETPRO DOS MS DNS CHAOS Denial of Service (CVE-2017-0171)",
    "ET DOS Possible Memcached DDoS Amplification Query (set)",
]

bruteforce_signatures = [
    "ET SCAN Multiple FTP Root Login Attempts from Single Source - Possible Brute Force Attempt",
    "ET SCAN Multiple FTP Administrator Login Attempts from Single Source - Possible Brute Force Attempt",
    "ET SCAN ICMP PING IPTools",
    "ET SCAN MYSQL 4.1 brute force root login attempt",
    "ET SCAN Medusa User-Agent",
    "ET SCAN ntop-ng Authentication Bypass via Session ID Guessing",
    "ET SCAN Rapid IMAPS Connections - Possible Brute Force Attack",
    "ET SCAN Rapid IMAP Connections - Possible Brute Force Attack",
    "GPL SQL sa brute force failed login attempt",
    "ET ATTACK_RESPONSE Frequent HTTP 401 Unauthorized - Possible Brute Force Attack",
    "ETPRO EXPLOIT Possible Novidade EK Attempting Intranet Router Compromise M7 (Bruteforce)",
]

servicedisc_signatures = [
    "ET SCAN Non-Allowed Host Tried to Connect to MySQL Server",
    "GPL SCAN SSH Version map attempt",
    "ET SCAN NMAP OS Detection Probe",
    "ETPRO SCAN Redis INFO Service Probe",
]

info_disc_signatures = [
    "ET SCAN PRO Search Crawler Probe",
    "ET SCAN Unusually Fast 400 Error Messages (Bad Request), Possible Web Application Scan",
    "ET SCAN Unusually Fast 404 Error Messages (Page Not Found), Possible Web Application Scan/Directory Guessing Attack",
    "ET SCAN Unusually Fast 403 Error Messages, Possible Web Application Scan",
    "ET SCAN Nessus FTP Scan detected (ftp_anonymous.nasl)",
    "ET SCAN Nessus FTP Scan detected (ftp_writeable_directories.nasl)",
    "ETPRO SCAN Nessus Scanner TFTP Get Attempt",
    "GPL SCAN Finger Version Query",
    "ETPRO SCAN Nessus Scanner TFTP Get Attempt",
    "ET SCAN NMAP SQL Spider Scan",
    "GPL SCAN Finger Account Enumeration Attempt",
    "ET SCAN MySQL Malicious Scanning 1",
    "ET SCAN SFTP/FTP Password Exposure via sftp-config.json",
    "ET SCAN Netsparker Scan in Progress",
    "ET SCAN DEBUG Method Request with Command",
    "ET SCAN DirBuster Scan in Progress",
    "ET SCAN Internet Scanning Project HTTP scan",
    "ET EXPLOIT FortiOS SSL VPN - Information Disclosure (CVE-2018-13379)"
]

vuln_disc_signatures = [
    "ET SCAN Havij SQL Injection Tool User-Agent Inbound",
    "ET SCAN Possible SQLMAP Scan",
    "ET SCAN DominoHunter Security Scan in Progress",
    "ET SCAN Potential muieblackcat scanner double-URI and HTTP library",
    "ET SCAN Apache mod_proxy Reverse Proxy Exposure 1",
    "ET SCAN COMMIX Command injection scan attempt",
    "ET SCAN Grendel-Scan Web Application Security Scan Detected",
    "ET SCAN WSFuzzer Web Application Fuzzing",
    "ET SCAN Wikto Scan",
    "ET SCAN Wikto Backend Data Miner Scan",
    "ET SCAN Wapiti Web Server Vulnerability Scan",
    "ET SCAN Suspicious User-Agent - get-minimal - Possible Vuln Scan",
    "ET SCAN SQLBrute SQL Scan Detected",
    "ET SCAN Possible Fast-Track Tool Spidering User-Agent Detected",
    "ET SCAN Metasploit WMAP GET len 0 and type",
    "ET SCAN Behavioral Unusual Port 137 traffic Potential Scan or Infection",
    "ET SCAN Behavioral Unusual Port 135 traffic Potential Scan or Infection",
    "ET SCAN Possible Scanning for Vulnerable JBoss",
    "ET SCAN Nmap NSE Heartbleed Response",
    "ETPRO SCAN NexusTaco Scanning for CVE-2014-3341",
]

hostdisc_signatures = [
    "ET SCAN Amap TCP Service Scan Detected",
    "ET SCAN Amap UDP Service Scan Detected",
    "ET SCAN Cisco Torch TFTP Scan",
    "ET SCAN Grim's Ping ftp scanning tool",
    "ET SCAN Modbus Scanning detected",
    "ET SCAN NMAP -sS window 2048",
    "ET SCAN NMAP -sO",
    "ET SCAN NMAP -sA (1)",
    "ET SCAN NMAP -f -sX"
    "ET SCAN Multiple NBTStat Query Responses to External Destination, Possible Automated Windows Network Enumeration",
    "ET SCAN NBTStat Query Response to External Destination, Possible Windows Network Enumeration",
    "ET SCAN Sipvicious Scan",
    "ET SCAN Modified Sipvicious User-Agent Detected (sundayddr)",
    "ET SCAN External to Internal UPnP Request udp port 1900",
    "ET SCAN DCERPC rpcmgmt ifids Unauthenticated BIND",
    "GPL SCAN SolarWinds IP scan attempt",
    "GPL SCAN Broadscan Smurf Scanner",
    "GPL SCAN ISS Pinger",
    "GPL SCAN PING CyberKit 2.2 Windows",
    "GPL SCAN PING NMAP",
    "GPL SCAN Webtrends Scanner UDP Probe",
    "GPL SCAN loopback traffic",
    "ET SCAN Httprecon Web Server Fingerprint Scan",
    "ETPRO SCAN Internal Machine Scanning VNC - Outbound Traffic",
    "ET SCAN ICMP Delphi Likely Precursor to Scan",
    "ETPRO SCAN IPMI Get Authentication Request (null seq number - null sessionID)",
    "ET SCAN ICMP =XXXXXXXX Likely Precursor to Scan",
    "ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap NSE)",
    "ET SCAN Non-Malicious SSH/SSL Scanner on the run",
    "ET SCAN NMAP SIP Version Detection Script Activity"
]

def_evasion_signatures = [
    "ET SCAN NNG MS02-039 Exploit False Positive Generator - May Conceal A Genuine Attack",
]

remote_serv_signatures = [
    "ET EXPLOIT Possible Palo Alto SSL VPN sslmgr Format String Vulnerability (Inbound)",
    "ET EXPLOIT Possible OpenVPN CVE-2014-6271 attempt",
]

user_priv_signatures = [
]

root_priv_signatures = [
    "ETPRO EXPLOIT Windows Diagnostics Hub Privilege Elevation Vuln Inbound (CVE-2016-3231) 1",
    "ETPRO EXPLOIT ATMFD.DLL Privilege Elevation Vuln (CVE-2016-3220)",
    "ETPRO EXPLOIT Possible CVE-2016-3219 Executable Inbound",
    "ETPRO EXPLOIT Win32k Privilege Elevation Vulnerability (CVE-2016-3254)",
    "ET EXPLOIT Possible MySQL cnf overwrite CVE-2016-6662 Attempt",
]

specific_exp_signatures = [
    #"ET EXPLOIT Possible IE Scripting Engine Memory Corruption Vulnerability (CVE-2019-0752)", #moved to arb
    #"ET EXPLOIT FortiOS SSL VPN - Pre-Auth Messages Payload Buffer Overflow (CVE-2018-13381)", #moved to net dos
    "ET EXPLOIT Possible OpenVPN CVE-2014-6271 attempt", #moved to arb
    "ET EXPLOIT Possible Palo Alto SSL VPN sslmgr Format String Vulnerability (Inbound)",
    #"ET EXPLOIT Potential Internet Explorer Use After Free CVE-2013-3163 Exploit URI Struct 1", #moved to arv
    "ET EXPLOIT QNAP Shellshock script retrieval",
    "ET EXPLOIT SolusVM 1.13.03 SQL injection",
    #"ETPRO EXPLOIT Microsoft Edge CSS History Information Disclosure Vulnerability (CVE-2016-7206)", #moved to arb
    "ET EXPLOIT IBM WebSphere - RCE Java Deserialization",
    #"ET EXPLOIT Possible iOS Pegasus Safari Exploit (CVE-2016-4657)",  #moved to arb
    "ET EXPLOIT Possible MySQL cnf overwrite CVE-2016-6662 Attempt",
    "ET EXPLOIT LastPass RCE Attempt",
    #"ETPRO EXPLOIT Possible Wget Arbitrary File Write Exploit Attempt (CVE-2016-4971)", #data deliv
    #"ETPRO EXPLOIT Internet Explorer Memory Corruption Vulnerability (CVE-2016-3211)", #arb
    "ETPRO EXPLOIT Possible HP.SSF.WebService Exploit Attempt",
    "ET EXPLOIT Possible Internet Explorer VBscript failure to handle error case information disclosure CVE-2014-6332 Common Construct M2",
    "ETPRO EXPLOIT Microsoft Office Memory Corruption Vulnerability Pointer Reuse (CVE-2016-0021)",
    "ET EXPLOIT TrendMicro node.js HTTP RCE Exploit Inbound (openUrlInDefaultBrowser)",
    "ET EXPLOIT Possible Postfix CVE-2014-6271 attempt",
    #"ETPRO EXPLOIT Possible HTML Meta Refresh (CVE-2015-6123) Inbound to Server", #arb
    #"ETPRO EXPLOIT Possible HTML Meta Refresh (CVE-2015-6123) via IMAP/POP3", #arb
    "ET EXPLOIT Possible Redirect to SMB exploit attempt - 303",
    #"ETPRO EXPLOIT MSXML3 Same Origin Policy SFB vulnerability 1 (CVE-2015-1646)", #exfil
    "ETPRO EXPLOIT Possible Jetty Web Server Information Leak Attempt",
    #"ETPRO EXPLOIT SChannel Possible Heap Overflow ECDSAWithSHA512 CVE-2014-6321", #arb
    "ETPRO EXPLOIT Netcore Router Backdoor Usage",
]

arbitary_exe_signatures = [
    "ET EXPLOIT FortiOS SSL VPN - Remote Code Execution (CVE-2018-13383)",
    "ETPRO EXPLOIT Possible EDGE OOB Access (CVE-2016-0193)",
    "ET EXPLOIT Seagate Business NAS Unauthenticated Remote Command Execution",
    "ET EXPLOIT Possible CVE-2014-6271 exploit attempt via malicious DNS",
    "ET EXPLOIT Possible Pure-FTPd CVE-2014-6271 attempt",
    "ET EXPLOIT Possible Qmail CVE-2014-6271 Mail From attempt",
    "ET EXPLOIT Possible IE Scripting Engine Memory Corruption Vulnerability (CVE-2019-0752)",
    "ET EXPLOIT Possible OpenVPN CVE-2014- 6271 attempt",
    "ET EXPLOIT Potential Internet Explorer Use After Free CVE-2013-3163 Exploit URI Struct 1",
    "ETPRO EXPLOIT Microsoft Edge CSS History Information Disclosure Vulnerability (CVE-2016-7206)",
    "ET EXPLOIT Possible iOS Pegasus Safari Exploit (CVE-2016-4657)",
    "ETPRO EXPLOIT Internet Explorer Memory Corruption Vulnerability (CVE-2016-3211)",
    "ETPRO EXPLOIT Possible HTML Meta Refresh (CVE-2015-6123) Inbound to Server",
    "ETPRO EXPLOIT Possible HTML Meta Refresh (CVE-2015-6123) via IMAP/POP3",
    "ETPRO EXPLOIT SChannel Possible Heap Overflow ECDSAWithSHA512 CVE-2014-6321",
]

exfiltration_signatures = [
    "ET EXPLOIT F5 BIG-IP rsync cmi authorized_keys successful exfiltration",
    "ETPRO EXPLOIT MSXML3 Same Origin Policy SFB vulnerability 1 (CVE-2015-1646)",
]

non_malicious_signatures = [ "SURICATA SMTP invalid reply",
"SURICATA SMTP invalid pipelined sequence",
"SURICATA SMTP no server welcome message",
"SURICATA SMTP tls rejected",
"SURICATA SMTP data command rejected",
"SURICATA HTTP gzip decompression failed",
"SURICATA HTTP request field missing colon",
"SURICATA HTTP invalid request chunk len",
"SURICATA HTTP invalid response chunk len",
"SURICATA HTTP invalid transfer encoding value in request",
"SURICATA HTTP invalid content length field in request",
"SURICATA TLS invalid SNI length",
"SURICATA TLS handshake invalid length",
"SURICATA DNS Unsolicited response",
"SURICATA DNS malformed response data",
"SURICATA DNS Not a response",
"ET POLICY Vulnerable Java Version 1.7.x Detected",
"ET POLICY Outdated Flash Version M1",
"ET POLICY OpenVPN Update Check",
"ET POLICY DynDNS CheckIp External IP Address Server Response",
]

attack_stage_mapping = {
    MicroAttackStage.END_POINT_DOS: endpointDoS_signatures,
    MicroAttackStage.NETWORK_DOS: networkDoS_signatures,
    MicroAttackStage.HOST_DISC : hostdisc_signatures,
    MicroAttackStage.VULN_DISC : vuln_disc_signatures,
    MicroAttackStage.INFO_DISC : info_disc_signatures,
    MicroAttackStage.BRUTE_FORCE_CREDS : bruteforce_signatures,
    MicroAttackStage.SERVICE_DISC : servicedisc_signatures,
    MicroAttackStage.SERVICE_SPECIFIC : specific_exp_signatures,
    MicroAttackStage.ARBITRARY_CODE_EXE : arbitary_exe_signatures,
    MicroAttackStage.ROOT_PRIV_ESC : root_priv_signatures,
    MicroAttackStage.USER_PRIV_ESC : user_priv_signatures,
    MicroAttackStage.REMOTE_SERVICE_EXP : remote_serv_signatures,
    MicroAttackStage.DEFENSE_EVASION : def_evasion_signatures,
    MicroAttackStage.DATA_EXFILTRATION : exfiltration_signatures,
    MicroAttackStage.NON_MALICIOUS : non_malicious_signatures,
}

unknown_mapping = {
    "SERVER-MYSQL MySQL/MariaDB Server geometry query object integer overflow attempt" : MicroAttackStage.END_POINT_DOS,
    "SERVER-MYSQL Multiple SQL products privilege escalation attempt" : MicroAttackStage.PRIV_ESC,
    "SERVER-MYSQL yaSSL SSL Hello Message buffer overflow attempt" : MicroAttackStage.ARBITRARY_CODE_EXE,
    "INDICATOR-SCAN User-Agent known malicious user-agent Masscan" : MicroAttackStage.HOST_DISC,
    "INDICATOR-SCAN DirBuster brute forcing tool detected" : MicroAttackStage.INFO_DISC,
    "INDICATOR-SCAN inbound probing for IPTUX messenger port" : MicroAttackStage.SERVICE_DISC,
    "INDICATOR-SCAN SSH brute force login attempt" : MicroAttackStage.BRUTE_FORCE_CREDS,
    "SERVER-APACHE Apache server mod_proxy reverse proxy bypass attempt" :  MicroAttackStage.PUBLIC_APP_EXP,
    "SERVER-APACHE Apache header parsing space saturation denial of service attempt" : MicroAttackStage.END_POINT_DOS,
    "SERVER-APACHE Apache malformed ipv6 uri overflow attempt": MicroAttackStage.END_POINT_DOS,
    "SERVER-APACHE Apache Struts remote code execution attempt - POST parameter" : MicroAttackStage.ARBITRARY_CODE_EXE,
    "SERVER-APACHE Apache APR header memory corruption attempt" : MicroAttackStage.END_POINT_DOS,
    "OS-WINDOWS Microsoft Windows DNS client TXT buffer overrun attempt" : MicroAttackStage.ARBITRARY_CODE_EXE,
    "INDICATOR-SCAN PHP backdoor scan attempt": MicroAttackStage.VULN_DISC,
    "INDICATOR-SCAN SSH Version map attempt" : MicroAttackStage.HOST_DISC,
    "INDICATOR-SCAN cybercop os probe" : MicroAttackStage.SERVICE_DISC,
    "INDICATOR-SCAN cybercop udp bomb" : MicroAttackStage.SERVICE_DISC,
    "PROTOCOL-FINGER account enumeration attempt" : MicroAttackStage.INFO_DISC,
    "MALWARE-CNC Win.Trojan.Crisis variant outbound connection" : MicroAttackStage.COMMAND_AND_CONTROL,
    "MALWARE-CNC Gozi trojan checkin" : MicroAttackStage.COMMAND_AND_CONTROL,
    "MALWARE-CNC Flame malware connection - /view.php" : MicroAttackStage.COMMAND_AND_CONTROL,
    "OS-LINUX Linux Kernel keyring object exploit download attempt" : MicroAttackStage.PRIV_ESC,
    "OS-LINUX Linux kernel ARM put_user write outside process address space privilege escalation attempt" : MicroAttackStage.PRIV_ESC,
    "OS-LINUX Linux kernel madvise race condition attempt" : MicroAttackStage.PRIV_ESC,
    "FILE-PDF PDF with click-to-launch executable" : MicroAttackStage.DATA_DELIVERY,
    "FILE-PDF Adobe Acrobat Reader PDF font processing memory corruption attempt" : MicroAttackStage.ARBITRARY_CODE_EXE,
    "OS-OTHER Bash environment variable injection attempt" : MicroAttackStage.ARBITRARY_CODE_EXE,
    "OS-OTHER Intel x86 side-channel analysis information leak attempt" : MicroAttackStage.DATA_EXFILTRATION,
    "OS-OTHER Mac OS X setuid privilege esclatation exploit attempt" : MicroAttackStage.PRIV_ESC,
    "FILE-EXECUTABLE Microsoft Windows Authenticode signature verification bypass attempt" : MicroAttackStage.ARBITRARY_CODE_EXE,
    "FILE-EXECUTABLE Microsoft CLFS.sys information leak attempt" : MicroAttackStage.DATA_EXFILTRATION,
    "FILE-EXECUTABLE Kaspersky Internet Security kl1.sys out of bounds read attempt" : MicroAttackStage.END_POINT_DOS,
    "FILE-EXECUTABLE XOR 0xfe encrypted portable executable file download attempt" : MicroAttackStage.DATA_DELIVERY,
    "FILE-EXECUTABLE Microsoft Windows NTFS privilege escalation attempt" : MicroAttackStage.PRIV_ESC,
    "INDICATOR-SHELLCODE ssh CRC32 overflow /bin/sh" : MicroAttackStage.ARBITRARY_CODE_EXE,
    "INDICATOR-SHELLCODE possible /bin/sh shellcode transfer attempt" : MicroAttackStage.DATA_DELIVERY,
    "FILE-FLASH Adobe Flash Player memory corruption attempt" : MicroAttackStage.PRIV_ESC,
    "FILE-FLASH Adobe Flash Player use after free attempt" : MicroAttackStage.PRIV_ESC,
    "FILE-IMAGE Oracle Java Virtual Machine malformed GIF buffer overflow attempt" : MicroAttackStage.PRIV_ESC,
    "FILE-IMAGE Adobe Acrobat TIFF Software tag heap buffer overflow attempt": MicroAttackStage.ARBITRARY_CODE_EXE,
    "FILE-JAVA Oracle Java privileged protection domain exploitation attempt" : MicroAttackStage.ARBITRARY_CODE_EXE,
    "FILE-JAVA Oracle Java sun.awt.image.ImagingLib.lookupByteBI memory corruption attempt" : MicroAttackStage.SERVICE_SPECIFIC,
    "FILE-JAVA Oracle Java RangeStatisticImpl sandbox breach attempt" : MicroAttackStage.SERVICE_SPECIFIC,
    "FILE-JAVA Oracle Java System.arraycopy race condition attempt" : MicroAttackStage.SERVICE_SPECIFIC,
    "BROWSER-CHROME Apple Safari/Google Chrome Webkit memory corruption attempt" : MicroAttackStage.ARBITRARY_CODE_EXE,
    "BROWSER-CHROME Google Chrome FileReader use after free attempt" : MicroAttackStage.PRIV_ESC,
    "BROWSER-CHROME V8 JavaScript engine Out-of-Memory denial of service attempt" : MicroAttackStage.END_POINT_DOS,
}


recent_suricata_alerts = {
    'ETPRO TROJAN TDrop CnC Checkin': MicroAttackStage.COMMAND_AND_CONTROL,
}


def get_attack_stage_mapping(signature):
    result = MicroAttackStage.NON_MALICIOUS
    if signature in usual_mapping.keys():
        result = usual_mapping[signature]
    elif signature in unknown_mapping.keys():
        result = unknown_mapping[signature]
    elif signature in ccdc_combined.keys():
        result = ccdc_combined[signature]
    else:
        for k,v in attack_stage_mapping.items():
            if signature in v:
                result = k
                break
    
    return micro_inv[str(result)]

# Program to find most frequent  
def most_frequent(serv): 
    return max(set(serv), key = serv.count) 
    
ser_groups = dict({
    'http(s)': ['http', 'https', 'ddi-udp-1', 'radan-http'],
    'wireless' : ['wap-wsp'],
    'voip': ['sip', 'sips'],
    'browser': ['vrml-multi-use'], 
    'searchEng': ['search-agent'],
    'broadcast': ['ssdp', 'snmp', 'commplex-main', 'icmpd', 'wsdapi'],
    'nameserver': ['domain', 'netbios-ns', 'menandmice-dns'],
    'remoteAccess': ['ssh', 'rfb', 'us-cli',  'ahsp', 'spt-automation', 'asf-rmcp', 'xdmcp', 'pcanywherestat', 'esmagent', \
                    'irdmi', 'epmap', 'wsman', 'icslap','ms-wbt-server', 'appiq-mgmt', 'sunrpc', 'mosaicsyssvc1'],
    'surveillance' : ['remoteware-cl', 'ads-c', 'syslog', 'websm', 'distinct'],

    'hostingServer': ['cslistener', 'etlservicemgr', 'web2host'],
    
    'printService' : ['pharos', 'ipps'],
    #'sendEmail': ['smtp'],
    
    'email': ['smtp', 'imaps', 'pop3', 'imap', 'pop3s', 'submission'],
    'authentication': ['kerberos', 'nv-video'], 
    'ATCcomm': ['cpdlc', 'fis'],
    
    'storage': ['http-alt', 'ncube-lm', 'postgresql', 'mysql', 'cm', 'ms-sql-s', 'ms-sql-m'],
    
    'dataSharing': ['ftp', 'pcsync-https', 'ndmp', 'netbios-ssn', 'microsoft-ds', 'profinet-rt', 'instantia'],
    'clocksync' : ['ntp'],
    
    'unassigned' : ['unknown', 'Unknown']
})

ser_inv = {}
for k,v in ser_groups.items():
    for x in v:
        ser_inv.setdefault(x,[]).append(k)
        
def load_IANA_mapping():
    """Download the IANA port-service mapping"""
    response = requests.get(IANA_CSV_FILE)
    if response.ok:
        content = response.content.decode("utf-8")
    else:
        raise RuntimeError('Cannot download IANA ports')
    table = csv.reader(content.splitlines())

    # Drop headers (Service name, port, protocol, description, ...)
    headers = next(table)

    # Note that ports might have holes
    ports = {}
    for row in table:
        # Drop missing port number, Unassigned and Reserved ports
        if row[1] and 'Unassigned' not in row[3]:# and 'Reserved' not in row[3]:
            
            # Split range in single ports
            if '-' in row[1]:
                low_port, high_port = map(int, row[1].split('-'))
            else:
                low_port = high_port = int(row[1])

            for port in range(low_port, high_port + 1):
                ports[port] = {
                    "name": row[0] if row[0] else "Unknown",
                    "description": row[3] if row[3] else "---",
                }
        else:
            # Do nothing 
            pass

    return ports
    
## 3
def readfile(fname):
    unparsed_data = None
    with open(fname, 'r') as f:
        unparsed_data = json.load(f)
    unparsed_data = unparsed_data[::-1]
    #print('# events: ', len(unparsed_data))
    #print(unparsed_data[0])
    return unparsed_data
    

#cats = dict()
#ips = dict()
#hosts = dict()
#h_trig = []

def parse(unparsed_data, alert_labels=[], slim=False, YEAR='2018'):
    
    FILTER = False
    badIP = '169.254.169.254'
    __cats = set()
    __ips = set()
    __hosts = set()
    __sev = set()
    data = []
    connections = dict()

    prev = -1
    for id, d in enumerate(unparsed_data):
        #print(d)
        
        raw = ''
        if YEAR=='2017':
             raw = json.loads(d['result']['_raw'])
        elif YEAR=='2018':
            raw = json.loads(d['_raw'])
        else:
            raw = d
        if raw['event_type'] != 'alert':
            continue
        #app_proto = raw['app_proto']
        host = ''
        if YEAR=='2017':
            try:
                host = raw['host']
            except:
                host = 'dummy'
        elif YEAR=='2018':
            host = d['host'][3:]
        else:
            host = 'dummy'
        #print(host)
        ts = raw['timestamp']
        dt = datetime.datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S.%f%z')# 2018-11-03T23:16:09.148520+0000
        DIFF = 0.0 if prev== -1 else round((dt - prev).total_seconds(),2)
        prev = dt
        
                
        sig = raw['alert']['signature']
        cat = raw['alert']['category']
        
        severity = raw['alert']['severity']

        if cat == 'Attempted Information Leak' and FILTER:
            continue
        srcip = raw['src_ip']
        srcport = None if 'src_port' not in raw.keys() else raw['src_port']
        dstip = raw['dest_ip']
        dstport = None if 'dest_port' not in raw.keys() else raw['dest_port']

        # Filtering out mistaken alerts / uninteresting alerts
        if srcip == badIP or dstip == badIP or cat == 'Not Suspicious Traffic':
            continue
            
        if not slim:
            mcat = get_attack_stage_mapping(sig)
            data.append((DIFF, srcip, srcport, dstip, dstport, sig, cat, host, dt, mcat))
        else:
            data.append((DIFF, srcip, srcport, dstip, dstport, sig, cat, host, dt))

        #host_ip.append((host, srcip, dstip))
       
        
        __cats.add(cat)
        __ips.add(srcip)
        __ips.add(dstip)
        __hosts.add(host)
        __sev.add(severity)

        
    '''_cats = [(id,c) for (id,c) in enumerate(__cats)]
    for (i,c) in _cats:
        if c not in cats.keys():
            cats[c] = 0 if len(cats.values())==0 else max(cats.values())+1
    _ips = [(id,ip) for (id,ip) in enumerate(__ips)]
    for (i,ip) in _ips:
        if ip not in ips.keys():
            ips[ip] = 0 if len(ips.values())==0 else max(ips.values())+1
    _hosts = [(id,h) for (id,h) in enumerate(__hosts)]
    for (i,h) in _hosts:
        if h not in hosts.keys():
            hosts[h] = 0 if len(hosts.values())==0 else max(hosts.values())+1'''
    
    #print(cats)
    #print(len(cats))
    #print(data[0][1], data[0][3])
    #print(data[1][1], data[1][3])
    print('Reading # alerts: ', len(data))
    
    if slim:
        print(len(data), len(alert_labels))
        j = 0
        for i,al in enumerate(alert_labels):
            spl = al.split(',')
            source = spl[0]
            dest = spl[1]
            mcat = int(spl[-1][:-1])
            cat = spl[2]
            
            if source == badIP or dest == badIP or cat == 'Not Suspicious Traffic':
                continue
            if spl[2] == 'Attempted Information Leak' and FILTER:
                continue
                
            if source == data[j][1] and dest == data[j][3]:
                
                data[j] += (mcat,)
            j += 1
    return data    

def removeDup(unparse, plot=False, t=1.0):
    
    if plot:
        orig, removed = dict(), dict()
        
        for _unparse in unparse:
            
            li = [x[9] for x in _unparse]
            
            for i in li:
                orig[i] = orig.get(i, 0) + 1
            print(orig.keys())
            
            li = [_unparse[x] for x in range(1,len(_unparse)) if _unparse[x][9] != 999 and not (_unparse[x][0] <= t  # Diff from previous alert is less than x sec
                                                              and _unparse[x][1] == _unparse[x-1][1] # same srcIP
                                                              and _unparse[x][3] == _unparse[x-1][3] # same destIP
                                                              and _unparse[x][5] == _unparse[x-1][5] # same suricata category
                                                              and _unparse[x][2] == _unparse[x-1][2] # same srcPort 
                                                              and _unparse[x][4] == _unparse[x-1][4] # same destPort
                                                                      )]
            li = [x[9] for x in li]
            for i in li:
                removed[i] = removed.get(i, 0) + 1
            print(removed.keys())
        
    else:
        
        
        li = [unparse[x] for x in range(1,len(unparse)) if unparse[x][9] != 999 and not (unparse[x][0] <= t  # Diff from previous alert is less than x sec
                                                              and unparse[x][1] == unparse[x-1][1] # same srcIP
                                                              and unparse[x][3] == unparse[x-1][3] # same destIP
                                                              and unparse[x][5] == unparse[x-1][5] # same suricata category
                                                              and unparse[x][2] == unparse[x-1][2] # same srcPort 
                                                              and unparse[x][4] == unparse[x-1][4] # same destPort
                                                            )]
        rem = [(unparse[x][9]) for x in range(1,len(unparse)) if  (unparse[x][0] <= t  # Diff from previous alert is less than x sec
                                                              and unparse[x][1] == unparse[x-1][1] # same srcIP
                                                              and unparse[x][3] == unparse[x-1][3] # same destIP
                                                              and unparse[x][5] == unparse[x-1][5] # same suricata category
                                                              and unparse[x][2] == unparse[x-1][2] # same srcPort 
                                                              and unparse[x][4] == unparse[x-1][4] # same destPort
                                                            )]
    if plot:
        print(orig)
        print(removed)
        b1 = dict(sorted(orig.items()))
        b2 = dict(sorted(removed.items()))
        print(b1.keys())
        print(b2.keys())
        # libraries
        import numpy as np
        import matplotlib.pyplot as plt
        import matplotlib.style
        import matplotlib as mpl
        mpl.style.use('default')

        fig = plt.figure(figsize=(20,20))

        # set width of bar
        barWidth = 0.4

        # set height of bar
        bars1 = [(x) for x in b1.values()]
        bars2 = [(x) for x in b2.values()]

        # Set position of bar on X axis
        r1 = np.arange(len(bars1))
        print(r1)
        r2 = [x + barWidth for x in r1]
        print('--', r2)

        # Make the plot
        plt.bar(r1, bars1, color='skyblue', width=barWidth, edgecolor='white', label='Raw')
        plt.bar(r2, bars2, color='salmon', width=barWidth, edgecolor='white', label='Cleaned')

        labs = [micro[x].split('.')[1] for x in b1.keys()]
        #print([x for x in b1.keys()])
        #print('ticks', [r + barWidth for r in range(len(b1.keys()))])
        # Add xticks on the middle of the group bars
        plt.ylabel('Frequency', fontweight='bold',fontsize='20')
        plt.xlabel('Alert categories', fontweight='bold',fontsize='20')
        plt.xticks( [x for x in r1], labs,fontsize='20', rotation='vertical')
        plt.yticks(fontsize='20')
        plt.title('High-frequency Alert Filtering', fontweight='bold',fontsize='20' )
        # Create legend & Show graphic
        plt.legend(prop={'size': 20})
        plt.show()

    print('Filtered # alerts (remaining)', len(li))
    return li
    
## 5

def load_data(path, t, mode= False):
    unparse = []
    team_labels = []
    files = glob.glob(path+"/*.json")
    print('About to read json files...')
    for f in files:
        name = os.path.basename(f)[:-5]
        print(name)
        team_labels.append(name)
        unparse_ = []
        if  not mode:
            unparse_ = parse(readfile(f), [], False)
        else:
            unparse_ = parse(reversed(readfile(f)), [], False, mode)
        unparse_ = removeDup(unparse_, t=t)
        unparse.append(unparse_)
        
    return (unparse, team_labels)
    
## 11
## Plotting for each team, how much categories are consumed
def plot_histogram(unparse, team_labels):
    # Choice of: Suricata category usage or Micro attack stage usage?
    SURICATA_SUMMARY = False
    cats = {'A Network Trojan was detected': 0, 'Generic Protocol Command Decode': 1, 'Attempted Denial of Service': 2, 'Attempted User Privilege Gain': 3, 'Misc activity': 4, 'Attempted Administrator Privilege Gain': 5, 'access to a potentially vulnerable web application': 6, 'Information Leak': 7, 'Web Application Attack': 8, 'Successful Administrator Privilege Gain': 9, 'Potential Corporate Privacy Violation': 10, 'Detection of a Network Scan': 11, 'Not Suspicious Traffic': 12, 'Potentially Bad Traffic': 13, 'Attempted Information Leak': 14}

    cols = ['b', 'r', 'g', 'c', 'm', 'y', 'k', 'olive', 'lightcoral', 'skyblue', 'mediumpurple', 'springgreen', 'chocolate', 'cadetblue', 'lavender']

    ids = [x for x,y in micro.items()]
    vals = [y for x,y in micro.items()]
    N = -1
    t = []

    if SURICATA_SUMMARY:
        N = len(cats)
        t = [[0]*len(cats) for x in range(len(unparse))]
    else:
        N = len(vals)
        t = [[0]*len(vals) for x in range(len(unparse))]
    ind = np.arange(N)    # the x locations for the groups
    width = 0.75       # the width of the bars: can also be len(x) sequence

    for tid,team in enumerate(unparse):
        count = 0
        for ev in team:
            #if ev[9] == 999:
            #    continue
            count += 1
            #print(ev[9])
            if SURICATA_SUMMARY:
                #if cats[ev[6]] != 14:
                    t[tid][cats[ev[6]]] += 1
            else:
                t[tid][ids.index(ev[9])] += 1 
        #print(count)
        for i,acat in enumerate(t[tid]):
            t[tid][i] = acat/len(team)
        #print('Total percentage: '+ str(sum(t[tid])), 'Actual len: ', str(len(team)))
    p = []
    for tid,team in enumerate(unparse):
        plot = None
        if tid == 0:
            plot = plt.bar(ind, t[tid], width)
        elif tid==1:
            plot = plt.bar(ind, t[tid], width,
                 bottom=t[tid-1]) 
        else:
            inde = [x for x in range(tid)]
            bot = np.add(t[0], t[1])
            for i in inde[2:]:
                bot = np.add(bot, t[i]).tolist()
            plot = plt.bar(ind, t[tid], width,
                 bottom=bot) 
        p.append(plot)

        # TODO: Decide whether to put it like this or normalize over columns
    #print(t)
    plt.ylabel('Percentage of occurance')
    plt.title('Frequency of alert category')
    if SURICATA_SUMMARY:
        plt.xticks(ind, ('c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'c10', 'c11', 'c12', 'c13', 'c14'))
    else:
        plt.xticks(ind, [x.split('.')[1] for x in vals], rotation='vertical')
    plt.tick_params(axis='x', which='major', labelsize=8)
    plt.tick_params(axis='x', which='minor', labelsize=8)
    #plt.yticks(np.arange(0, 13000, 1000))
    plt.legend([plot[0] for plot in p], team_labels)
    plt.tight_layout()
    #plt.show() 
    return plt

## 14
def legend_without_duplicate_labels(ax, fontsize=10, loc='upper right'):
    handles, labels = ax.get_legend_handles_labels()
    unique = [(h, l) for i, (h, l) in enumerate(zip(handles, labels)) if l not in labels[:i]]
    unique = sorted(unique, key = lambda x: x[1])
    ax.legend(*zip(*unique), loc=loc, fontsize=fontsize) 
    
## 13
# Goal: (1) To first form a collective attack profile of a team
# and then (2) TO compare attack profiles of teams
def getepisodes(action_seq, plot, debug=False):
    
    dx = 0.1
    #print(h_d_mindata)
    y = [len(x) for x in action_seq]#
    if not debug:
        #print('-------------- strat')
        
        if len(y) <= 1:
            #print(sum(y), len(y), 'yo returning')
            return []
        #if (sum(y) > 0):
        ##    print('how long? = ', sum(y))
        #   print(y)
            '''fig = plt.figure()
            plt.plot(y)
            plt.show()'''
    # test case 1: normal sequence
    #y = [11, 0, 0, 2, 5, 2, 2, 2, 4, 2, 0, 0, 8, 6, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 13, 1, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 9, 2]
    # test case 2: start is not detected
    #y = [ 0, 2, 145, 0, 0, 1, 101, 45, 0, 1, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    # test case 2.5: start not detected (unfinfihed)
    #y = [39, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 28, 0, 2, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 0, 0, 1, 1, 2, 1, 2, 2, 1, 1, 1, 2, 0, 1, 2, 0, 2, 1, 1, 1, 2, 1, 1, 0, 1, 1, 1, 1]
    # test case 3: last peak not detected (unfinsihed)
    #y = [36, 0, 0, 0, 2, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 17, 0, 0, 0, 0, 0, 0, 33, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 6, 5, 6, 1, 2, 2]
    # test case 4: last peak undetected (finished)
    #y = [1, 0, 0, 1, 3, 0, 1, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    # test case 5: end peak is not detected
    #y = [1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 3, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 2, 0]
    # test case 6: end peak uncompleted again not detected:
    #y = [8, 4, 0, 0, 0, 4, 0, 0, 5, 0, 0, 1, 10, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 2]
    # test case 7: single peak not detected (conjoined)
    #y = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 207, 0, 53, 24, 0, 0, 0, 0, 0, 0, 0]
    # test case 8: another single peak not detected
    #y = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    # test case 9: single peak at the very end
    #y = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 294]
    # test acse 10: ramp up at end
    #y = [0, 0, 0, 0, 190, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 300, 38, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 271, 272]
    #print(y)
    #y = [1, 0, 64, 2]
    #y = [2, 0, 0, 0, 0, 0, 0, 2, 3, 0, 0, 0, 0, 2, 3]
    #y = [1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]

    cap  = max(y)+1
    dy = diff(y)/dx
    

    dim = len(dy)
    #print(list(zip(y[:dim],dy[:dim])))
    
    positive = [(0, dy[0])]
    positive.extend( [(ind, dy[ind]) for ind in range(1, dim) if (dy[ind-1]<=0 and dy[ind] > 0 )])# or ind-1 == 0]
    negative = [(ind+1, dy[ind+1]) for ind in range(0, dim-1) if (dy[ind] < 0 and dy[ind+1] >= 0)]
    if dy[-1] < 0: # special case for last ramp down thats not fully gone down
        negative.append((len(dy), dy[-1]))
    elif dy[-1] > 0: # special case for last ramp up without any ramp down
        #print('adding somthing at the end ', (len(dy), dy[-1]))
        negative.append((len(dy), dy[-1]))
 
   
    common = list(set(negative).intersection(positive))
    negative = [item for item in negative if item not in common]
    positive = [item for item in positive if item not in common]
    
    #print('--', [x[0] for x in negative] , len(y))
    negative = [x for x in negative if (y[x[0]] <= 0 or x[0] == len(y)-1)]
    positive = [x for x in positive if (y[x[0]] <= 0 or x[0] == 0)]
    
    #print(positive)
    #print(negative)
    
    if len(negative) < 1 or len(positive) < 1:
        return []

    episodes_ = [] # Tuple (startInd, endInd)
    for i in range(len(positive)-1):
        ep1 = positive[i][0]
        ep2 = positive[i+1][0]
        ends = []
        for j in range(len(negative)):

            if negative[j][0] >= ep1 and negative[j][0] < ep2:
                    ends.append(negative[j])
        
        if len(ends) > 0:
            episode = (ep1, max([x[0] for x in ends]))
            episodes_.append(episode)
    if (len(positive) == 1 and len(negative) == 1):
        episode = (positive[0][0], negative[0][0])
        episodes_.append(episode)
        
    if (len(episodes_) > 0 and negative[-1][0] != episodes_[-1][1] ):  
        episode = (positive[-1][0], negative[-1][0])
        episodes_.append(episode)
     
    
    if (len(episodes_) > 0 and positive[-1][0] != episodes_[-1][0]):# and positive[-1][0] < episodes[-1][1]): 
        elim = [x[0] for x in common]
        if len(elim) > 0 and max(elim) > positive[-1][0]:
            episode = (positive[-1][0], max(elim))
            episodes_.append(episode)
            
    if (len(episodes_) == 0 and len(positive) == 2 and len(negative) == 1):
        episode = (positive[1][0], negative[0][0])
        episodes_.append(episode)
    
    if plot:
        plt.plot(y, 'gray')
        for ep in episodes_:
            #print(ep)
            xax_start = [ep[0]]*cap
            xax_end = [ep[1]]*cap
            yax = list(range(cap))

            plt.plot(xax_start, yax, 'g', linestyle=(0, (5, 10)))
            plt.plot(xax_end, yax, 'r', linestyle=(0, (5, 10)))

        plt.show()
    #print('number episodes ', len(episodes_))
    return episodes_

def aggregate_into_episodes(unparse, team_labels, step=150):
    cols = ['b', 'r', 'g', 'c', 'm', 'y', 'k', 'olive', 'lightcoral', 'skyblue', 'mediumpurple', 'springgreen', 'chocolate', 'cadetblue', 'lavender']

    PRINT = False
    interesting = []
    # Reorganize data for each attacker per team 
    team_data = dict()
    s_t = dict()
    for tid,team in enumerate(unparse):
        #attackers = list(set([x[1] for x in team])) # collecting all src ip
        #attackers.extend(list(set([x[3] for x in team]))) # collection all dst ip
        #attackers = [x for x in attackers if x not in hostip.keys()] # filtering only attackers
        
        
        host_alerts = dict()

        for ev in team:
            #print(ev[0])
            h = ev[7]
            s = ev[1]
            d = ev[3]
            c = ev[9]
            ts = ev[8]
            sp = ev[2] if ev[2] != None else 65000 
            dp = ev[4] if ev[4] != None else 65000
            # Simply respect the source,dst format! (Correction: source is always source and dest alwyas dest!)

            source, dest, port = -1, -1, -1
            #print(s, d, sp, dp)
            #assert sp >= dp
            
            source = s #if s not in inv_hostip.keys() else inv_hostip[s]
            dest = d #if d not in inv_hostip.keys() else inv_hostip[d]
            # explicit name if cant resolve
            #port = str(dp) if (dp not in port_services.keys() or port_services[dp] == 'unknown') else port_services[dp]['name'] 
            
            # say unknown if cant resolve it
            port = 'unknown' if (dp not in port_services.keys() or port_services[dp] == 'unknown') else port_services[dp]['name']
            
            if (source,dest) not in host_alerts.keys() and (dest,source) not in host_alerts.keys():
                host_alerts[(source,dest)] = []
                #print(tid, (source,dest), 'first', ev[8])
                s_t[str(tid)+"|"+str(source)+"->"+str(dest)] = ev[8]
                
            if((source,dest) in host_alerts.keys()):
                host_alerts[(source,dest)].append((dest, c, ts, port)) # TODO: remove the redundant host names
                #print(source, dest, (micro[c].split('.'))[-1], port)
            else:
                host_alerts[(dest,source)].append((source, c, ts, port))
                #print(dest,source, (micro[c].split('.'))[-1], port)

        team_data[tid] = host_alerts.items()
        
    # Calculate number of alerts over time for each attacker 
    #print(len(s_t))
    team_episodes = []

    startTimes = [x[0][8] for x in unparse]
    team_times = []

    mcats = list(micro.keys())
    mcats_lab = [x.split('.')[1] for x in micro.values()]
    for tid, team in team_data.items():
        print('----------------TEAM '+str(tid)+'-------------------------')
        t_ep = dict()
        _team_times = dict()
        for attacker, alerts in team:
            #if re.search('[a-z]', attacker):
            #    continue
            #if attacker != ('corp-mail-00', 'corp-onramp-00'):
            #    continue
            
            if len(alerts) <= 1:
                #print('kill ', attacker)
                continue
            
            #print(attacker, len([(x[1]) for x in alerts])) # TODO: what about IPs that are not attacker related?
            first_elapsed_time = round((alerts[0][2]-startTimes[tid]).total_seconds(),2)
            
            # debugging if start times of each connection are correct.
            #print(first_elapsed_time, round( (s_t[str(tid)+"|"+str(attacker[0])+"->"+str(attacker[1])] - startTimes[tid]).total_seconds(),2))
            last_elapsed_time = round((alerts[-1][2] - alerts[0][2]).total_seconds() + first_elapsed_time,2)
            #print(first_elapsed_time, last_elapsed_time)
            
            _team_times['->'.join(attacker)] = (first_elapsed_time, last_elapsed_time)
            ts = [x[2] for x in alerts]
            rest = [(x[0], x[1], x[2], x[3]) for x in alerts]

            prev = -1
            DIFF = []
            relative_elapsed_time = []
            for timeid, dt in enumerate(ts):
                if timeid == 0:
                    DIFF.append( 0.0)#round((dt - startTimes[tid]).total_seconds(),2) )
                else:
                    DIFF.append( round((dt - prev).total_seconds(),2) )
                prev = dt
            #print(DIFF[:5])
            assert(len(ts) == len(DIFF))
            elapsed_time = list(accumulate(DIFF))
            relative_elapsed_time = [round(x+first_elapsed_time,2) for x in elapsed_time]
            
            
            assert(len(elapsed_time) == len(DIFF))

            t0 = int(first_elapsed_time)#int(relative_elapsed_time[0])
            tn = int(relative_elapsed_time[-1])
            
            #step = 150 # 2.5 minute fixed step. Can be reduced or increased depending on required granularity

            h_ep = []
            #mindatas = []
            for mcat in mcats:
                
                mindata = []
                for i in range(t0, tn, step):
                    li = [a for d,a in zip(relative_elapsed_time, rest) if (d>=i and d<(i+step)) and a[1] == mcat]  
                    mindata.append(li) # alerts per 'step' seconds

                #print([len(x) for x in mindata])
                episodes = []
                
                
                episodes = getepisodes(mindata, False)

                if len(episodes) > 0:
                    
                    events  = [len(x) for x in mindata]
                   
                    minute_info = [(x[0]*step+t0, x[1]*step+t0) for x in episodes]

                    raw_ports = []
                    
                    for e in mindata:
                        if len(e) > 0:
                            raw_ports.append([(x[3]) for x in e])
                        else:
                            raw_ports.append([])

                    _flat_ports = [item for sublist in raw_ports for item in sublist]

                    episode = [(mi[0], mi[1], mcat, events[x[0]:x[1]+1], 
                                   raw_ports[x[0]:x[1]+1]) 
                                 for x,mi in zip(episodes, minute_info)] # now the start and end are actual elapsed times
                    
                    #EPISODE DEF: (startTime, endTime, mcat, rawevents, epiVolume, epiPeriod, epiServices)
                    episode = [(x[0], x[1], x[2], x[3], round(sum(x[3])/float(len(x[3])),1), (x[1]-x[0]),
                                [item for sublist in x[4] for item in sublist]) for x in episode]
                    
                    h_ep.extend(episode) 

            if len(h_ep) == 0:
                continue
            # artifically adding tiny delay for events that are exactly at the same time
            h_ep.sort(key=lambda tup: tup[0])
            minute_info = [x[0] for x in h_ep]
            minute_info2 = [minute_info[0]]
            tiny_delay= 1
            for i in range(1, len(minute_info)):
                if i == 0:
                    pass
                else:
                    if (minute_info[i]==(minute_info[i-1])):
                        minute_info2.append(  minute_info2[-1]+tiny_delay)
                    else:
                        minute_info2.append(minute_info[i])
            h_ep = [(minute_info2[i],x[1],x[2],x[3],x[4],x[5], x[6]) for i,x in enumerate(h_ep)]
            t_ep[attacker] = h_ep
            if PRINT:
                fig = plt.figure(figsize=(10,10))
                ax = plt.gca()
                plt.title('Micro attack episodes | Team: '+str(tid) +' | Host: '+ '->'.join([x for x in attacker]))
                plt.xlabel('Time Window (sec)')
                plt.ylabel('Micro attack stages')
                # NOTE: Line thicknesses are on per host basis
                tmax= max([x[4] for x in h_ep])
                tmin = min([x[4] for x in h_ep])
                for idx, ep in enumerate(h_ep):
                    #print(idx, (ep[0], ep[1]), ep[2], ep[3][ep[0]:ep[1]+1])
                    xax = list(range(ep[0], ep[1]+1))
                    yax = [mcats.index(ep[2])]*len(xax)
                    thickness  = ep[4]
                    lsize = ((thickness - tmin)/ (tmax - tmin)) * (5-0.5) + 0.5 if (tmax - tmin) != 0.0 else 0.5
                    #lsize = np.log(thickness) + 1 TODO: Either take log or normalize between [0.5 5]
                    msize = (lsize*2)+1
                    ax.plot(xax, yax, color=mcols[macro_inv[micro2macro[micro[ep[2]]]]], linewidth=lsize)
                    ax.plot(ep[0], mcats.index(ep[2]), color=mcols[macro_inv[micro2macro[micro[ep[2]]]]], marker='.', linewidth=0, markersize=msize, label=micro2macro[micro[ep[2]]])
                    ax.plot(ep[1], mcats.index(ep[2]), color=mcols[macro_inv[micro2macro[micro[ep[2]]]]], marker='.', linewidth=0, markersize=msize)
                    plt.yticks(range(len(mcats)), mcats_lab, rotation='0')
                legend_without_duplicate_labels(ax)
                plt.grid(True, alpha=0.4)
                
                #plt.tight_layout()
                #plt.savefig('Pres-Micro-attack-episodes-Team'+str(tid) +'-Connection'+ attacker[0]+'--'+attacker[1]+'.png')
                plt.show()
        
        team_episodes.append(t_ep)
        team_times.append(_team_times)
    return (team_episodes, team_times)
            
## 17

#### Host = [connections] instead of team level representation
def host_episode_sequences(team_episodes):
    host_data = {}
    #team_host_data= []
    print(len(team_episodes))

    for tid, team in enumerate(team_episodes):
        print('----- TEAM ', tid, ' -----')
        print(len(set([x[0] for x in team.keys()])))
        for attacker,episodes in team.items():
            #print(attacker)
            if len(episodes) < 2:
                continue
            perp= attacker[0]
            vic = attacker[1]
            #print(perp)
            #if ('10.0.0' in perp or '10.0.1' in perp):
            #        continue
            
            att = 't'+str(tid)+'-'+perp
            #print(att)
            if att not in host_data.keys():
                host_data[att] = []   
            ext = [(x[0], x[1], x[2], x[3], x[4], x[5], x[6], vic) for x in episodes]

            host_data[att].append(ext)
            host_data[att].sort(key=lambda tup: tup[0][0])
            
    print(len(host_data))   

    team_strat = list(host_data.values())
    #print(len(team_strat[0]), [(len(x)) for x in team_strat[0]])
    #print([[a[2] for a in x] for x in team_strat[0]])  
    return (host_data)        

def break_into_subbehaviors(host_data):        
    attackers = []
    keys = []
    alerts = []
    cutlen = 4
    FULL_SEQ= False
        
    #print(len(team))
    for tid, (atta,victims) in enumerate(host_data.items()):
        print('----- Sequence # ', tid, ' -----')
        #print(atta)
        #print(len(victims))
        for episodes in victims:
            if len(episodes) < 2:
                continue
            victim = episodes[0][7]
            pieces = math.floor(len(episodes)/cutlen)
            _episodes = []
            if FULL_SEQ:
                att = atta+'->'+victim
                #print(att, [x[2] for x in episodes])
                keys.append(att)
                alerts.append(episodes)

            else:
                if pieces < 1:
                    att = atta+'->'+victim+'-0'
                    #print('---', att, [x[2] for x in episodes])
                    keys.append(att)
                    alerts.append(episodes)
                else:
                    c = 0
                    ep = [x[2] for x in episodes]
                    #print(ep)
                    cuts = [i for i in range(len(episodes)-1) if (len(str(ep[i])) > len(str(ep[i+1]))) ]#(ep[i] > 100 and ep[i+1] < 10)]
                    #print(cuts)
                    if len(cuts) == 0:
                        att = atta+'->'+victim+'-0'
                        #print('---', att, [x[2] for x in episodes])
                        keys.append(att)
                        alerts.append(episodes)
                        #pass
                    else:
                        rest = (-1,-1)
                       
                        for i in range(len(cuts)):
                            start, end = 0, 0
                            if i == 0:
                                start = 0
                                end = cuts[i]  
                            else:
                                start = cuts[i-1]+1
                                end = cuts[i]
                            rest = (end+1, len(ep)-1)
                            al = episodes[start:end+1]
                            if len(al) < 2:
                                print('discrding-1', [x[2] for x in al], start, end, len(episodes))
                                continue
                            att = atta+'->'+victim+'-'+str(c)
                            #print('---', att, [x[2] for x in al])
                            keys.append(att)
                            alerts.append(al)
                            c+=1
                        #print('--', ep[rest[0]: rest[1]+1])
                        al = episodes[rest[0]: rest[1]+1]
                        if len(al) < 2:
                            print('discrding-2', [x[2] for x in al]) # TODO This one is not cool1
                            continue
                        att = atta+'->'+victim+'-'+str(c)
                        #print('---', att, [x[2] for x in al])
                        keys.append(att)
                        alerts.append(al)
    print('# sub-sequences', len(keys))
    return (alerts, keys)

## 27 Aug 2020: Generating traces for flexfringe 
def generate_traces(alerts, keys, datafile, test_ratio=0.0):
    victims = alerts
    al_services = [[most_frequent(y[6]) for y in x] for x in victims]
    print('all unique servcies')
    print(set([item for sublist in al_services for item in sublist]))
    print('---- end')

    count_lines = 0
    count_cats = set()

    f = open(datafile, 'w')#'C:\\Users\\anadeem1\\Downloads\\dfasat\\data\\test.txt', 'w')
    lengths = []
    lines = []
    for i,episodes in enumerate(victims):
        #print(episodes)
        num_behav = keys[i].split('-')[-1]
        #print(keys[i], num_behav)
        if len(episodes) < 3:
            continue
        #lengths+= len(episodes)
        count_lines += 1
        mcats = [str(x[2]) for x in episodes]
        num_servs = [len(set((x[6]))) for x in episodes]
        max_servs = [ser_inv[most_frequent(x[6])][0] for x in episodes]
        stime = [x[0] for x in episodes]
        #print(stime)
        #print(' '.join(mcats))

        #multi = [str(c)+":"+str(n)+","+str(s) for (c,s,n) in zip(mcats,max_servs,num_servs)] # multivariate case
        multi = [str(small_mapping[int(c)])+"|"+str(s) for (c,s,n,st) in zip(mcats,max_servs,num_servs, stime)] # merging mcat and serv into one
        #print(multi)
        for e in multi:
            feat = e.split(':')[0]
            count_cats.add(feat)
        multi.reverse()
        st = '1' + " "+ str(len(mcats)) + ' ' + ' '.join(multi) + '\n'
        #f.write(st)
        lines.append(st)
    f.write(str(count_lines) + ' ' + str(len(count_cats)) + '\n')
    for st in lines:
        f.write(st)
    f.close()
    #print(lengths, lengths/float(count_lines))
    
## 2 sept 2020: Learning the model
def flexfringe(*args, **kwargs):
  """Wrapper to call the flexfringe binary

   Keyword arguments:
   position 0 -- input file with trace samples
   kwargs -- list of key=value arguments to pass as command line arguments
  """  
  command = ["--help"]

  if(len(kwargs) >= 1):
    command = []
    for key in kwargs:
      command += ["--" + key + "=" + kwargs[key]]

  result = subprocess.run(["C:\\Users\\Geert\\Desktop\\Thesis\\flexfringe\\flexfringe.exe",] + command + [args[0]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
  print(result.returncode, result.stdout, result.stderr)

  
  try:
    with open("dfafinal.dot") as fh:
      return fh.read()
  except FileNotFoundError:
    pass
  
  return "No output file was generated."

def show(data):
  """Show a dot string as (inline-) PNG

    Keyword arguments:
    data -- string formated in graphviz dot language to visualize
  """
  if data=="":
    pass
  else:
    g = graphviz.Source(data, format="png")
    g.render()
    display(Image(g.render()))
   
def loadmodel(modelfile):

  """Wrapper to load resulting model json file

   Keyword arguments:
   modelfile -- path to the json model file
  """  

  # because users can provide unescaped new lines breaking json conventions
  # in the labels, we are removing them from the label fields
  with open(modelfile) as fh:
    data = fh.read()
  data = re.sub( r'\"label\" : \"([^\n|]*)\n([^\n]*)\"', r'"label" : "\1 \2"', data )
  
  data = data.replace('\n', '').replace(',,', ',')#.replace(', ,', ',')#.replace('\t', ' ')


  data = re.sub(',+', ',', data)
  machine = json.loads(data)


  dfa = defaultdict(lambda: defaultdict(str))

  for edge in machine["edges"]:
      dfa[ edge["source"] ][ edge["name"] ] = (edge["target"], edge["appearances"])

  for entry in machine["nodes"]:
      dfa[ str(entry['id']) ]["type"] = "0"
      dfa[str(entry['id']) ]["isred"] = int(entry['isred'])

  return (dfa, machine)

def traverse(dfa, sinks, sequence, statelist=False):
  """Wrapper to traverse a given model with a string

   Keyword arguments:
   dfa -- loaded model
   sequence -- space-separated string to accept/reject in dfa
  """  
  #print(dfa)
  in_main_model = set()
  sinks = dict() ## REMOVE IT!!!
  state = "0"
  stlst = ["0"]
  #print('This seq', sequence.split(" "))
  for event in sequence.split(" "):
      sym = event.split(":")[0]
      
      #print('curr symbol ', sym, 'state no.', dfa[state][sym]) 
      
      state = dfa[state][sym]
      isred = 0
      
      if state != "":
         isred = dfa[state[0]]["isred"]
      #print(state)
      #if state != "":
      if isred == 1:
            in_main_model.add(state[0])
      if state == "":
          # return -1 for low sev symbols
          sev = rev_smallmapping[sym.split('|')[0]]
          #print(sev)
          if len(str(sev)) >= 2:
                #print('high-sev sink found', sev)
                #print(stlst[-1], sinks[stlst[-1]], stlst)
                try:
                    state = sinks[stlst[-1]][sym][0]
                except:
                    #print('didnt work for', sequence, 'done so far:', stlst)
                    state = '-1'
          else:
              state = '-1'
          #print("Must look in sinks")
          #print('prev symb: ', sym, 'and prev state no.', stlst[-1])
          #print('BUT this last state no in sink gives ', sinks[stlst[-1]][sym])
          #print('curr sym', sym)
          #print('previous state no.:', stlst[-1], 'results in sink id:', sinks[stlst[-1]][sym] )
          #if sinks[stlst[-1]][sym] == "":
                
                #print('prob')
                #print(sequence)
                #state = '-1'
          #else:
          #      state = sinks[stlst[-1]][sym][0]
          #
          #if not statelist:
          #        return dfa[state]["type"] == "1"
          #else:
          #        return (dfa[state]["type"] == "1", stlst)

      else:
          try:
              #print('weird place')
              # take target id, discard counts
              state = state[0]
          except IndexError:
              print("Out of alphabet: alternatives")
          
              stlst.append("-1")
              if not statelist:
                     return dfa[state]["type"] == "1"
              else:
                     return (dfa[state]["type"] == "1", stlst)
      stlst.append(state)

  if not statelist:
      return dfa[state]["type"] == "1"
  else:
      return (dfa[state]["type"] == "1", stlst)

def encode_sequences(m, m2):
    #print(m2)
    traces = []
    sp = []
    orig = []
    with open(path_to_traces) as tf:
        lines = tf.readlines()[1:]
    #print(len(lines))

    for line in lines:
        if line == lines[-1]:
             spl = line.split(' ')
        else:
            spl = line[:-1].split(' ')
        
        line = ' '.join(spl[2:])
        #print(spl[2:])
        orig.append([(x) for x in spl[2:] if x != ''])
        traces.append(line)
    num_sink = 0   
    total = 0
    state_traces = dict()
    for i,sample in enumerate(traces):
        #print(sample)
        r, s = traverse(m, m2, sample, statelist=True)
        s = [(x) for x in s]
        sp.append(s)
        state_traces[i] = s

        total += len(s)
        true = [1 if x == '-1' else 0 for x in s]
        
        num_sink += sum(true)
        
        print('encoded', sample, state_traces[i])
        assert (len(sample.split(' '))+1 == len(state_traces[i]))

    #print(len(traces), len(state_traces))
    print('traces in sink:', num_sink, 'total', total, 'percentage:',100*(num_sink/float(total)))
    return (traces, state_traces)    

def find_severe_states(traces, m, m2):
    med_states = set()
    sev_states = set()
    for i,sample in enumerate(traces):    
        r, s = traverse(m, m2, sample, statelist=True)
        s = s[1:]
        sample = sample.split(' ')
        #print([(x,rev_smallmapping[x[0].split('|')[0]]) for x in zip(sample, s)])
        med = [int(state) for sym, state in zip(sample, s) if len(str(rev_smallmapping[sym.split('|')[0]])) == 2 ]
        med_states.update(med)
        #print(s)
        sev = [int(state) for sym, state in zip(sample, s) if len(str(rev_smallmapping[sym.split('|')[0]])) == 3 ]
        #print([(sym) for sym, state in zip(sample, s) if len(str(rev_smallmapping[sym.split('|')[0]])) == 3 ])
        sev_states.update(sev)
        #if not set(sev_states).isdisjoint(s):
        #    print(sample)
        #    print('--', s)
    #print(med_states)
    #print(sev_states)
    #print('med-sev traces')
    #for i,sample in enumerate(traces):
    med_states = med_states.difference(sev_states)  
        
    #    r, s = traverse(m, m2, sample, statelist=True)
    #    s = [int(x) for x in s]
    #    #print(s)
    #    if not set(med_states).isdisjoint(s):
    #        print(sample)
    #        print('--', s)
    print('Total medium states', len(med_states))  
    print('Total severe states', len(sev_states))
    return(med_states, sev_states)

## collecting sub-behaviors back into the same trace -- condensed_data is the new object to deal with
def make_condensed_data(alerts, keys, state_traces, med_states, sev_states):
    levelone = set()
    levelone_ben = set()
    condensed_data = dict()
    counter = -1
    for tid, (attacker, episodes) in enumerate(zip(keys, alerts)):

        if len(episodes) < 3:
            continue
        #print(' ------------- COUNTER ', counter, '------')
        counter += 1
        if '10.0.254' not in attacker:
            continue
        if ('147.75' in attacker or '69.172'  in attacker):
                continue
        tr = [int(x) for x in state_traces[counter]]
        #print(counter)
        num_servs = [len(set((x[6]))) for x in episodes]
        max_servs = [most_frequent(x[6]) for x in episodes]
        #print(max_servs)
        
        if 0 in tr and (not set(tr).isdisjoint(sev_states) or not set(tr).isdisjoint(med_states)):
            levelone.add(tr[tr.index(0)+1])
       
        #print([x[2] for x in episodes]) 
        #print(state_traces[counter])
        new_state = (state_traces[counter][1:])[::-1]
        
        #print(new_state, [x[2] for x in episodes])
        # also artifically add tiny delay so all events are not exactly at the same time.
        #print(len(episodes), new_state, max_servs)
        times = [(x[0], x[1], x[2], int(new_state[i]), max_servs[i]) for i,x in enumerate(episodes)] # start time, endtime, episode mas, state ID
        
        step1 = attacker.split('->')
        step1_0 = step1[0].split('-')[0]
        step1_1 = step1[0].split('-')[1]
        step2 = step1[-1].split('-')[0]
        real_attacker = '->'.join([step1_0+'-'+step1_1, step2])
        real_attacker_inv = '->'.join([step1_0+'-'+step2, step1_1])
        #print(real_attacker)
        INV = False
        if '10.0.254' in step2:
            INV = True
        
        if real_attacker not in condensed_data.keys() and real_attacker_inv not in condensed_data.keys():
            if INV:
                condensed_data[real_attacker_inv] = []
            else:
                condensed_data[real_attacker] = []
        if INV:
            condensed_data[real_attacker_inv].extend(times)
            condensed_data[real_attacker_inv].sort(key=lambda tup: tup[0])  # sorts in place based on starting times
        else:
            condensed_data[real_attacker].extend(times)
            condensed_data[real_attacker].sort(key=lambda tup: tup[0])  # sorts in place based on starting times
        
    #print(len(condensed_data), counter)
    #print([c for c in condensed_data.values()][:5])
      
    #print('High-severity objective states', levelone, len(levelone))
    return condensed_data
    

def make_state_groups(condensed_data, datafile):
    state_groups = {
    }
    all_states = set()
    gcols = ['lemonchiffon', 'gold', 'khaki', 'darkkhaki', 'beige', 'goldenrod', 'wheat', 'papayawhip', 'orange', 'oldlace', 'bisque']
    for att,episodes in condensed_data.items():
        #print([(x[2],x[3]) for x in episodes])

        state = [(x[2],x[3]) for x in episodes]
        all_states.update([x[3] for x in episodes])
        ## Sanity check
        '''for s in serv:
            FOUND= False
            for group,ser in ser_groups.items():
                if s in ser:
                    #print(s, '--', group)
                    FOUND= True
                    break
            if not FOUND:
                print('--- not found', s)'''
        
        for i,st in enumerate(state):
            #print(state[i])
            macro = micro2macro[micro[st[0]]].split('.')[1]
            
            if st[1] == -1 or st[1] == 0: #state[i] == -1 or state[i] == 0:
                continue
            if macro not in state_groups.keys():
                state_groups[macro] = set()
        
            state_groups[macro].add(st[1])
            
    #state_groups['ACTIVE_RECON'] = state_groups['ACTIVE_RECON'].difference(state_groups['PRIVLEDGE_ESC'])  
    #state_groups['PASSIVE_RECON'] = state_groups['PASSIVE_RECON'].difference(state_groups['PRIVLEDGE_ESC'])  
          
    #print([(x) for x in state_groups.values()])      
    #print((all_states))
    model = open(datafile+".ff.final.dot", 'r')
    lines = model.readlines()
    model.close()
    written = []
    outlines = []
    outlines.append('digraph modifiedDFA {\n')
    for gid, (group, states) in enumerate(state_groups.items()):
        print(group)
        outlines.append('subgraph cluster_'+group+' {\n')
        outlines.append('style=filled;\n')
        outlines.append('color='+gcols[gid]+';\n')
        outlines.append('label = "' + group + '";\n')
        for i,line in enumerate(lines):
                pattern = '\D+(\d+)\s\[\slabel="\d.*'
                SEARCH = re.match(pattern, line)
                if SEARCH:
                    
                    matched = int(SEARCH.group(1))
                    #print(matched)
                    if matched in states:
                        c = i
                        while '];' not in lines[c]:
                            #print(lines[c])
                            outlines.append(lines[c])
                            written.append(c)
                            c += 1
                        #print(lines[c])
                        outlines.append(lines[c])
                        written.append(c)
                    elif matched not in all_states and group == 'ACTIVE_RECON':
                        if matched != 0:
                            c = i
                            while '];' not in lines[c]:
                                #print(lines[c])
                                outlines.append(lines[c])
                                written.append(c)
                                c += 1
                            #print(lines[c])
                            outlines.append(lines[c])
                            written.append(c)
                            state_groups['ACTIVE_RECON'].add(matched)
                        print('ERROR: manually handled', matched, ' in ACTIVE_RECON')
                # 0 -> 1 [label=
                '''pattern2 = '\D+(\d+)\s->\s(\d+)\s\[label=.*'
                SEARCH = re.match(pattern2, line)
                if SEARCH:
                    matched = int(SEARCH.group(1))
                    print(line)
                    if matched in states:
                        c = i
                        while '];' not in lines[c]:
                            #print(lines[c])
                            outlines.append(lines[c])
                            written.append(c)
                            c += 1
                        #print(lines[c])
                        outlines.append(lines[c])
                        written.append(c)
                '''
        outlines.append('}\n')
        #break
        
        
    for i,line in enumerate(lines):
        if i < 2:
            continue
        if i not in written:
            outlines.append(line)
    #outlines.append('}\n')

    outfile = open('spdfa-clustered-'+datafile+'-dfa.dot', 'w')
    for line in outlines:
        outfile.write(line)
    outfile.close()

    outfile = 'spdfa-clustered-'+datafile
    os.system("dot -Tpng "+outfile+"-dfa.dot -o "+outfile+"-dfa.png")
    return state_groups

def make_av_data(condensed_data):
## Experiment: attack graph for one victim w.r.t time
    condensed_v_data= dict()
    for attacker,episodes in condensed_data.items():
        team = attacker.split('-')[0]
        victim = attacker.split('->')[1]
        tv = team+'-'+victim
        #print(tv)
        if tv not in condensed_v_data.keys():
            condensed_v_data[tv] = []
        condensed_v_data[tv].extend(episodes)
        condensed_v_data[tv] = sorted(condensed_v_data[tv], key=lambda item: item[0])
    condensed_v_data = {k: v for k, v in sorted(condensed_v_data.items(), key=lambda item: len([x[0] for x in item[1]]))}
    #print([(k,len([x[0] for x in v])) for k,v in condensed_v_data.items()])
    print('victims', (set([x.split('-')[-1] for x in condensed_v_data.keys()])))

    condensed_a_data= dict()
    for attacker,episodes in condensed_data.items():
        team = attacker.split('-')[0]
        victim = (attacker.split('->')[0]).split('-')[1]
        tv = team+'-'+victim
        #print(tv)
        if tv not in condensed_a_data.keys():
            condensed_a_data[tv] = []
            
        condensed_a_data[tv].extend(episodes)
        condensed_a_data[tv] = sorted(condensed_a_data[tv], key=lambda item: item[0])
        #print(len(condensed_a_data[tv]))
    #condensed_a_data = {k: v for k, v in sorted(condensed_a_data.items(), key=lambda item: item[1][0][0])}
    #print([(k,[x[0] for x in v]) for k,v in condensed_a_data.items()])
    print('attackers', (set([x.split('-')[1] for x in condensed_a_data.keys()])))
    return (condensed_a_data, condensed_v_data)
 
## Per-objective attack graph for dot: 14 Nov (final attack graph) 
def make_AG(condensed_v_data, condensed_data, state_groups, datafile, expname):  
    
    tcols = {
        't0': 'maroon',
        't1': 'orange',
        't2': 'darkgreen',
        't3': 'blue',
        't4': 'magenta',
        't5': 'purple',
        't6': 'brown',
        't7': 'tomato',
        't8': 'turquoise',
        't9': 'skyblue',
        
    }
    SAVE = True
    if SAVE:
        try:
            #if path.exists('AGs'):
            #    shutil.rmtree('AGs')
            dirname = expname+'AGs'
            os.mkdir(dirname)
        except:
            print("Can't cerate directory here")
        else:
            print("Successfully created directory for AGs")
    
    
    
    #tcols = {'t0': 'saddlebrown'}
    #int_victim = []#['10.128.0.205']#['10.0.1.40', '10.0.1.41','10.0.1.42','10.0.1.43','10.0.1.44' ]

    shapes = ['oval', 'oval', 'oval', 'box', 'box', 'box', 'box', 'hexagon', 'hexagon', 'hexagon', 'hexagon', 'hexagon']
    ser_total = dict()
    simple = dict()
    for intvictim in list(condensed_v_data.keys()):
        int_victim = intvictim.split('-')[1]
        #team=intvictim.split('-')[0]
        print('!!!_-------', int_victim)
        attacks = []
        A_lab, S_lab, stimes = [], [], []
        collective = dict()
        for att,episodes in condensed_data.items():
            service_theme = []
            this_times = []
            #print(len(episodes))
            #print([(x[2],x[3]) for x in episodes])
            for ep in episodes:

                time = math.ceil(ep[0]/1.0)
                encode = [group for group,sts in state_groups.items() if ep[3] in sts]
                cat= -1
                if len(encode) == 0:
                    #continue
                    cat = micro[ep[2]].split('.')[1]
                    stateID = '|Sink' if len(str(ep[2])) == 1 else '|Sink'
                else:
                    cat = str(encode[0])#str(encode[0]) if 'RECON' in encode[0] else str(encode[0])+'|'+str(ep[3]) 
                    stateID = '' if 'RECON' in encode[0] else '|'+str(ep[3]) 

                sorting= None
                try:
                    short = cat#.split('|')[0]
                    sorting = macro_inv['MacroAttackStage.'+short]
                except:
                    sorting =  -1
                #A_lab.append((sorting, cat))
                this_times.append(time)
                stimes.append(time)   
                servtheme = str(micro[ep[2]].split('.')[1])+'|'+str(ep[4]) + str(stateID)
                service_theme.append(servtheme)
                if len(str(ep[2])) ==3:
                    attacks.append(servtheme)
                S_lab.append((ep[2], servtheme))
            #print(service_theme)        

            #A_lab = list(set(A_lab))
            S_lab = list(set(S_lab))

            #A_lab = sorted(A_lab, key=lambda x: x[0])

            S_lab = sorted(S_lab, key=lambda x: macro_inv[micro2macro[micro[x[0]]]])

            stimes = sorted(list(set(stimes)))

            #alab = [x[1] for x in A_lab]
            slab = [x[1] for x in S_lab]

            collective[att] = (service_theme,this_times)
        attacks = list(set(attacks))
        # Experiment 1: state IDs are not important. Attack graph should show all mas+service
        attacks = [x.split('|')[0]+'|'+x.split('|')[1] for x in attacks]
        # Experiment 2: state IDs and service are not important. Attack graph should show all mas
        #attacks = [x.split('|')[0] for x in attacks]
        attacks = list(set(attacks))
        #print(attacks)
        #path_info = dict()
        #print(len(set(slab)))
        #print(collective.keys())
        #print([(k,len(x[0])) for k,x in collective.items()])
        #print(collective['t1-10.0.254.202'])
        for attack in attacks:#, 'DATA_DELIVERY|cslistener|27', 'DATA_EXFILTRATION|http|13']:# , , 'DATA_DESTRUCTION|us-cli|955', 'RESOURCE_HIJACKING|http|14']: 
            
            #if attack not in path_info.keys():
            #    path_info[attack] = {'t0': [], 't1': [], 't2': [], 't3': [], 't4': [], 't5': []}
                
            #if obj_ser not in ser_total.keys():
            #    ser_total[obj_ser] = set()
            collect = dict()
            event_set = set()
            time_set = set()
            team_level = dict()
            sseen = []
            nodes = set()
            vertices, edges = 0, 0
            for att,episodes in condensed_data.items():
                #print(att)
                team = att.split('-')[0]
                #print([(x[3],x[0]) for x in episodes])
                event = []
                times = []
                #print(att)

                for ep in episodes:
                    time = round(ep[0]/1.0)
                    encode = [group for group,sts in state_groups.items() if ep[3] in sts]
                    cat= -1
                    if len(encode) == 0:
                        #continue
                        cat = micro[ep[2]].split('.')[1]
                        stateID = '|Sink' if len(str(ep[2])) == 1 else '|Sink'
                    else:
                        cat = str(encode[0])#str(encode[0]) if 'RECON' in encode[0] else str(encode[0])+'|'+str(ep[3]) 
                        stateID = '' if 'RECON' in encode[0] else '|'+str(ep[3]) 
                        #sorting= None
                        #try:
                        #    short = cat#.split('|')[0]
                        #    sorting = macro_inv['MacroAttackStage.'+short]
                        #except:
                        #    sorting =  -1
                        #stimes.append(time)   

                    servtheme = str(micro[ep[2]].split('.')[1])+'|'+str(ep[4]) + str(stateID)
                    times.append(time)
                    event.append(servtheme)

                    #if len(str(ep[2])) ==3:
                    #    attacks.append(servtheme)
                    #S_lab.append((ep[2], servtheme))
                #print(times)
                if not sum([True if attack in x else False for x in event]):
                    continue
                if int_victim not in att:
                    continue
                #print('-------!!!!', attack)
                #obj_ser = ser_inv[attack.split('|')[1]][0]
                #print('-------!!!SERVICE', attack.split('|')[1])
                #print([x for x in event])
                #print([x for x in times])
                event_set = set(event_set)
                time_set = set(time_set)

                event_set.update(event)
                time_set.update(times)


                event_set = sorted(event_set, key=lambda x: macro_inv[micro2macro['MicroAttackStage.'+x.split('|')[0]]])
                time_set = sorted(time_set)

                data = [(x,y) for x,y in zip(event,times)]
                #cuts = [i for i in range(len(event)-1) if (len(str(micro_inv['MicroAttackStage.'+event[i].split('|')[0]])) > \
                #                                           len(str(micro_inv['MicroAttackStage.'+event[i+1].split('|')[0]]))) ]#
                #print('+++++', cuts)

                lists = []
                l = []

                '''for i,d in enumerate(data):
                    if i in cuts:
                        l.append(d)
                        if len(l) <= 1: ## If only a single node, reject
                            l = []
                            continue

                        if attack in l[-1][0]:
                            sseen.append(d[0])
                            lists.append(l)
                        l = []

                        continue
                    l.append(d)
                if len(l) > 1 and attack in l[-1][0]:
                    sseen.append(l[-1][0])
                    lists.append(l)'''
                for d in data:
                    if attack in d[0]:
                        l.append(d) 
                        if len(l) <= 1: ## If only a single node, reject
                            l = []
                            continue
                        #print(len(l))
                        lists.append(l)
                        l = []
                        sseen.append(d[0])
                        continue
                    l.append(d)
                #print(lists)
                #print([[y[0] for y in x] for x in lists])
                if team not in team_level.keys():
                    team_level[team] = []
                team_level[team].extend(lists)
                #team_level[team] = sorted(team_level[team], key=lambda item: item[1])
            #print(sseen)
            # print('elements in graph', team_level.keys(), sum([len(x) for x in team_level.values()]))

            if sum([len(x) for x in team_level.values()]) == 0:
                continue
            
            name = attack.replace('|', '').replace('_','').replace('-','').replace('(','').replace(')', '')
            lines = []
            lines.append((0,'digraph '+ name + ' {'))
            lines.append((0,'rankdir="BT";'))
            lines.append((0, '"'+attack+'" [shape=doubleoctagon, style=filled, fillcolor=salmon];'))
            lines.append((0, '{ rank = max; "'+attack+'"}'))
            for s in list(set(sseen)):
                lines.append((0,'"'+s+'" -> "'+attack+'"'))
                #print(s, s.split('|')[1], ser_inv[s.split('|')[1]][0])
                
                #o = ser_inv[s.split('|')[1]][0]
                #if o not in ser_total.keys():
                #    ser_total[o] = set()
                #ser_total[o].add(s)
            for s in list(set(sseen)):
                lines.append((0,'"'+s+'" [style=filled, fillcolor= salmon]'))
            #print('-------!!!numObjs', set(sseen))
            
            samerank = '{ rank=same; "'+ '" "'.join(sseen)
            samerank += '"}'
            lines.append((0,samerank))


            for k,vs in team_level.items():
                for v in vs:
                    #if v[0][1] == 89141:
                    #    continue
                    nodes.update([x[0] for x in v])
            
            for k,vs in team_level.items():
                ones = [''.join([y[0] for y in x]) for x in vs]
                #print(ones)
                unique = len(set(ones))
                #print(unique)
                #print('team', k, 'total paths', len(vs), 'unique paths', unique, 'longest path:', max([len(x) for x in vs]), \
                #     'shortest path:', min([len(x) for x in vs]))
                
                #path_info[attack][k].append((len(vs), unique, max([len(x) for x in vs]), min([len(x) for x in vs])))
                for v in vs:
                    #print(v[1])
                    #if v[0][1] == 89141:
                    #    continue
                            
                    color = tcols[k]
                    bi = zip(v, v[1:])
                    for vid,(one,two) in enumerate(bi):
                        
                        if vid == 0:
                            if 'Sink' in one[0]:
                                lines.append((0,'"'+one[0]+'" [style="dotted,filled", fillcolor= yellow]'))
                            else:
                                lines.append((0,'"'+one[0]+'" [style=filled, fillcolor= yellow]'))
                        else:
                            if 'Sink' in one[0]:
                                line = [x[1] for x in lines]
                                
                                partial = '"'+one[0]+'" [style="dotted'
                                #print(line)
                                #print('@@@@', partial)
                                if not sum([True if partial in x else False for x in line]):
                                    lines.append((0,partial+'"]'))
                            elif 'Sink' in two[0]:
                                line = [x[1] for x in lines]
                                partial = '"'+two[0]+'" [style="dotted'
                                #print(line)
                                #print('@@@@', partial)
                                if not sum([True if partial in x else False for x in line]):
                                    lines.append((0,partial+'"]'))
                                #lines.append((0,'"'+two[0]+'" [style="dotted"]'))
                        #edges += 1
                        lines.append((one[1], '"'+one[0]+'"' + ' -> ' + '"'+two[0]+'"' +' [ label='+ str(one[1]) +']' + '[ color='+color+']')) # 
            #lines = sorted(lines, key=lambda item: item[0], reverse=True)
            #print(lines)
            #print(nodes)
            for node in nodes:
                #vertices += 1
                mas = node.split('|')[0]
                mas = macro_inv[micro2macro['MicroAttackStage.'+mas]]
                shape = shapes[mas]
                lines.append((0,'"'+node+'" [shape='+shape+']'))
            lines.append((1000,'}'))
            
            for l in lines:
                if '->' in l[1]:
                    edges +=1
                elif 'shape=' in l[1]:
                    vertices +=1
                    
            
            simple[int_victim+'-'+name] = (vertices, edges)
            #print('# vert', vertices, '# edges: ', edges,  'simplicity', vertices/float(edges))
            #print('file')
            if SAVE:
                v = int_victim#.replace('.','')
                f = open(dirname+'/'+datafile+'-attack-graph-for-victim-'+v+'-'+name +'.dot', 'w')
                for l in lines:
                    #print(l[1])
                    f.write(l[1])
                    f.write('\n')
                f.close()
                out_f_name = datafile+'-attack-graph-for-victim-'+v+'-'+name 
                os.system("dot -Tpng "+dirname+'/'+out_f_name+".dot -o "+dirname+'/'+out_f_name+".png")
                #print('~~~~~~~~~~~~~~~~~~~~saved')
            print('----')
        #print('total high-sev states:', len(path_info))
        #path_info = dict(sorted(path_info.items(), key=lambda kv: kv[0]))
        #for k,v in path_info.items():
        #    print(k)
        #    for t,val in v.items():
        #       print(t, val)
    #for k,v in ser_total.items():
    #    print(k, len(v), set([x.split('|')[0] for x in v]))
 
 
 
 
 
 
## ----- main ------    
### Load port numbers and services (from Andrea Corsini)

if len(sys.argv) < 5:
    print('USAGE: ag-gen.py {path/to/json/files} {experiment-name} {alert-filtering-window (def=1.0)} {alert-aggr-window (def=150)} {mode}')
    sys.exit()
folder = sys.argv[1]
expname = sys.argv[2]
t = float(sys.argv[3])
w = int(sys.argv[4])
rev = False
if len(sys.argv) >= 6:
    rev = sys.argv[5]
    
# saddr = 'C:\\Users\\anadeem1\\Downloads\\dfasat\\data\\' # path_to_flexfringe installation
# outaddress = ""#"C:\\Users\\anadeem1\\Downloads\\dfasat\\"
# path_to_ini = "C:\\Users\\anadeem1\\Downloads\\dfasat\\ini\\batch-likelihoodRIT.ini"

saddr = "C:\\Users\\Geert\\Desktop\\Thesis\\flexfringe\\flexfringe.exe"
outaddress = ""#"C:\\Users\\anadeem1\\Downloads\\dfasat\\"
path_to_ini = "C:\\Users\\Geert\\Desktop\\Thesis\\AD-Attack-Graph\\src\\data\\s_pdfa.ini"

modelname = expname+'.txt'#'test-trace-uni-serGroup.txt'
datafile = expname+'.txt'#'trace-uni-serGroup.txt'
   
path_to_traces = datafile


port_services = load_IANA_mapping()

print('----- Reading alerts ----------')
(unparse, team_labels) = load_data(folder, t, rev) # t = minimal window for alert filtering
plt = plot_histogram(unparse, team_labels)
plt.savefig('data_histogram-'+expname+'.png')
print('------ Converting to episodes ---------')
team_episodes,_ = aggregate_into_episodes(unparse, team_labels, step=w) # step = w
print('---- Converting to episode sequences -----------')
host_data  =  host_episode_sequences(team_episodes)
print('----- breaking into sub-sequences and making traces----------')
(alerts, keys) = break_into_subbehaviors(host_data)
generate_traces(alerts, keys, datafile)


print('------ Learning SPDFA ---------')
# Learn S-PDFA
flexfringe(path_to_traces, ini=path_to_ini, symbol_count="2", state_count="4")

## Copying files
outfile = (outaddress+datafile)
o = (outaddress+modelname)
os.system("dot -Tpng "+outfile+".ff.final.dot -o "+o+".png")
#files = [ datafile+'.ff.final.dot', datafile+'.ff.final.dot.json', datafile+'.ff.sinksfinal.json', datafile+'.ff.init_dfa.dot', datafile+'.ff.init_dfa.dot.json']
#outfiles = [ modelname+'.ff.final.dot', modelname+'.ff.final.dot.json', modelname+'.ff.sinksfinal.json', modelname+'.ff.init_dfa.dot', modelname+'.ff.init_dfa.dot.json']
#for (file,out) in zip(files,outfiles):
#    copyfile(outaddress+file, outaddress+out)
    
path_to_model = outaddress+modelname

print('------ !! Special: Fixing syntax error in sinks files  ---------')
with open(path_to_model+".ff.sinksfinal.json", 'r') as file:
    filedata = file.read()
filedata = ''.join(filedata.rsplit(',', 1))
with open(path_to_model+".ff.sinksfinal.json", 'w') as file:
    file.write(filedata)
    
'''with open(path_to_model+".ff.final.dot.json", 'r') as file:
    filedata = file.read()
filedata = ''.join(filedata.rsplit(',', 1))
with open(path_to_model+".ff.final.dot.json", 'w') as file:
    file.write(filedata)'''

print('------ Loading and traversing SPDFA ---------')
# Load S-PDFA
m, data = loadmodel(path_to_model+".ff.final.dot.json")
m2,data2 = loadmodel(path_to_model+".ff.sinksfinal.json")

print('------- Encoding into state sequences --------')
# Encoding traces into state sequences  
(traces, state_traces) = encode_sequences(m,m2)
(med_states, sev_states) = find_severe_states(traces, m, m2)    
condensed_data = make_condensed_data(alerts, keys, state_traces, med_states, sev_states)

print('------- clustering state groups --------')
state_groups = make_state_groups(condensed_data, modelname)
(condensed_a_data, condensed_v_data) = make_av_data(condensed_data)

print('------- Making alert-driven AGs--------')
make_AG(condensed_v_data, condensed_data, state_groups, modelname, expname)

print('------- FIN -------')
## ----- main END ------  

