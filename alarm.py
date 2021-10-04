#!/usr/bin/python3

from struct import pack
from scapy.all import *
import argparse
from scapy.layers import http
import base64



'''
packetcallback()
--------------------------------------------------------------------------
  Input: packet (scapyObject)
  Output: None, void function

  Function: Based on the port, the function first gets the credentials from
  IMAP, FTP, and HTTP packets. It then checks for scans on the using the flags
  in the packet. 
--------------------------------------------------------------------------
'''
def packetcallback(packet):
  try:
    if 'IP' in packet:
      ip_src = packet['IP'].src
      if 'TCP' in packet:
        # Collect the flags on the packet
        flags = packet['TCP'].flags
        # Establish the destination port
        dest_port = packet['TCP'].dport
        payload = getPayload(packet)
        if dest_port == 21:    # FTP
          getFTPCredentials(payload)
        elif dest_port == 143: # IMAP
          getIMAPCredentials(payload)   
        elif packet.haslayer('HTTPRequest'):  # HTTP on any port
          getHTTPCredentials(payload)
        check_for_scans(flags, ip_src, 'TCP', dest_port, payload)
  except:
    pass



'''
outputScanAlarm():
--------------------------------------------------------------------------
  Input: protocol (str) -> name of protocol of the scan
         payload (str) -> payload of the packet
         incident (str) -> name of the scan
         ip_src (str) -> source of the scan
  Output: None, void function

  Function: Outputs the scanner that was found
--------------------------------------------------------------------------
'''
def outputScanAlarm(incident:str, ip_src:str, protocol:str, payload:str) -> None:
  global incident_num
  print("ALERT #{}: {} is detected from {} ({}) ({})!".format(incident_num, incident, ip_src, protocol, payload))
  incident_num += 1



'''
check_for_scans():
--------------------------------------------------------------------------
  Input: flags (str) -> flags on the packet
         ip_src (str) -> source of the scan
         dest_port (int) -> destination port of the packet
         protocol_name (str) -> name of protocol of the scan
         payload (str) -> payload of the packet
  Output: None, void function

  Function: Based on the flag combinations and destination port, calls the 
  correct scan output. 
--------------------------------------------------------------------------
'''
def check_for_scans(flags, ip_src, protocol_name, dest_port, payload) -> None:
  # XMAS Scan
  if ("F" and "P" and "U") in flags:
    outputScanAlarm("Xmas scan", ip_src, protocol_name, payload)
  # FIN Scan
  elif "F" == flags:
    outputScanAlarm("Fin scan", ip_src, protocol_name, payload)
  # NULL Scan
  elif not flags:
    outputScanAlarm("Null scan", ip_src, protocol_name, payload)
  # Nikto Scan
  elif (dest_port == 80 and payload.find('Nikto') != -1):
    outputScanAlarm("Nikto scan", ip_src, protocol_name, payload)
  # RDP Scan
  elif (dest_port == 3389) and ("S" == flags):
    outputScanAlarm("RDP scan", ip_src, protocol_name, payload)
  



'''
outputCredentialsAlarm():
--------------------------------------------------------------------------
  Input: protocol (str) -> name of protocol where the credentials were found
         username (str) -> username found after parsing
         password (str) -> password found after parsing
  Output: None, void function

  Function: Outputs the credentials found.
--------------------------------------------------------------------------
'''
def outputCredentialsAlarm(protocol:str, username:str, password:str) -> None:
  global incident_num
  print("ALERT #{}: Usernames and passwords sent in-the-clear ({}) (username:{}, password:{})".format(incident_num, protocol, username, password))
  incident_num += 1



'''
getHTTPCredentials():
--------------------------------------------------------------------------
  Input: payload (str)
  Output: None, void function

  Function: Utilizes the base64 library to decode the encrypted string that
  follows "Authorization Basic ". The username and password are parsed 
  out and passed into the outputCredentialsAlarm().
--------------------------------------------------------------------------
'''
def getHTTPCredentials(payload:str) -> None:
  # Get the indices of the base64 encoded username and password
  protocol_name = "HTTP"
  basicIndex = payload.find("Basic")
  if (basicIndex != -1):
    credentials = base64.b64decode(payload[basicIndex:].replace("\r\n", " ").split(" ")[1]).decode('utf-8').split(':')
    outputCredentialsAlarm(protocol_name, credentials[0], credentials[1])



'''
getFTPCredentials():
--------------------------------------------------------------------------
  Input: payload (str)
  Output: None, void function

  Function: Utilizes a global hashmap, ftpCredentials. If username and 
  password is present, output the credential alarm and reset the hashmap.
  Using words_in_string, username and passwords are parsed and input into 
  the hashmap. This is required because the username and password are passed
  in different packets.
--------------------------------------------------------------------------
'''
def getFTPCredentials(payload:str) -> None:
  global ftpCredentials
  protocol_name = "FTP"
  username_list = ['USER', 'user', 'USERNAME', 'username', 'UID', 'uid']
  password_list = ['PASS', 'pass', 'PASSWORD', 'password', 'Password']
  
  # Outputs an alarm and resets the ftpCredentials dictionary once a username/password pair has been identified
  if ('username' in ftpCredentials) and ('password' in ftpCredentials):
    outputCredentialsAlarm(protocol_name, ftpCredentials['username'], ftpCredentials['password'])
    ftpCredentials = {}
  # Find the username 
  if not ('username' in ftpCredentials):
    if words_in_string(username_list, payload):
      ftpCredentials['username'] = payload.replace("\r\n", "").split(' ')[1]
  # Find the password 
  if not ('password' in ftpCredentials):
    if words_in_string(password_list, payload):
      ftpCredentials['password'] = payload.replace("\r\n", "").split(' ')[1]



'''
getIMAPCredentials():
--------------------------------------------------------------------------
  Input: payload (str)
  Output: None, void function

  Function: Checks if there is a LOGIN present in the IMAP present. Strips
  and cleans the payload, parsing out the username and password, which is
  then fed into the outputCredentialsAlarm for output.
--------------------------------------------------------------------------
'''
def getIMAPCredentials(payload:str) -> None:
  protocol_name = "IMAP"
  login_list = ['LOGIN', 'login']
  if words_in_string(login_list, payload):
      username = payload.replace("\r\n", "").split(' ')[2] 
      password = payload.replace("\r\n", "").split(' ')[3]
      outputCredentialsAlarm(protocol_name, username, password)



'''
getPayload():
--------------------------------------------------------------------------
  Input: packet (scapyObject)

  Function: Checks if there is either Raw or HTTPRequest content in the 
  packet and returns as  a string. If there is no content return 'Empty'.
--------------------------------------------------------------------------
'''
def getPayload(packet) -> str:   
  if Raw in packet or packet.haslayer('HTTPRequest'):
    payload = bytes(packet['TCP'].payload).decode('utf-8')
    return payload
  else:
    return "Empty"
  


'''
words_in_string():
--------------------------------------------------------------------------
  Input: word_list (list[str]) -> list of keywords
         a_string (str) -> string to be searched

  Function: Checks if a word from a word_list is in a_string

  References: From StackOverflow comment reply, https://stackoverflow.com/
  questions/14769162/find-matching-words-in-a-list-and-a-string
--------------------------------------------------------------------------
'''
def words_in_string(word_list:list[str], a_string:str) -> set:
  return set(word_list).intersection(a_string.split())



parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()


'''
Globals for finding credentials and number of incidents 
'''
incident_num = 1
ftpCredentials = {}

if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")