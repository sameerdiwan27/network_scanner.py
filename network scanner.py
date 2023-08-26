#!/usr/bin/env python3

import scapy.all as scapy
import argparse


def ip_range():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Define the target ip range")
    options = parser.parse_args()
    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast_arp_request = broadcast / arp_request
    answered = scapy.srp(broadcast_arp_request, timeout=1, verbose=False)[0]
    all_list = []
    for information in answered:
        all_dict ={"ip": information[1].psrc, "mac": information[1].hwsrc, }
        all_list.append(all_dict)
    return all_list


def print_information(print_result):
    print("IP ADDRESS\t\t  MAC ADDRESS\n...............................................")
    for result in print_result:
        print(result["ip"] + "\t\t" + result["mac"])


def whole_network_scanner_script():
    option = ip_range()
    scan_result = scan(option.target)
    print_information(scan_result)


whole_network_scanner_script()
