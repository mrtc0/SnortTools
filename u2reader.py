#!/usr/bin/env python3

import os
import time
import datetime
import sys
import argparse
from idstools import unified2, maps

PROTOCOLS = {\
    0:"HOPOPT", 1:"ICMP", 2:"IGMP", 3:"GGP", 4:"IPv4", 5:"ST", 6:"TCP", 7:"CBT", 8:"EGP", 9:"IGP",\
    10:"BBN-RCC-MON", 11:"NVP-II", 12:"PUP", 14:"EMCON", 15:"XNET", 16:"CHAOS", 17:"UDP", 18:"MUX", 19:"DCN-MEAS",\
    20:"HMP", 21:"PRM", 22:"XNS-IDP", 23:"TRUNK-1", 24:"TRUNK-2", 25:"LEAF-1", 26:"LEAF-2", 27:"RDP", 28:"IRTP", 29:"ISO-TP4",\
    30:"NETBLT", 31:"MFE-NSP", 32:"MERIT-INP", 33:"DCCP", 34:"3PC", 35:"IDPR", 36:"XTP", 37:"DDP", 38:"IDPR-CMTP", 39:"TP++",\
    40:"IL", 41:"IPv6", 42:"SDRP", 43:"IPv6-Route", 44:"IPv6-Frag", 45:"IDRP", 46:"RSVP", 47:"GRE", 48:"DSR", 49:"BNA",\
    50:"ESP", 51:"AH", 52:"I-NLSP", 54:"NARP", 55:"MOBILE", 56:"TLSP", 57:"SKIP", 58:"IPv6-ICMP", 59:"IPv6-NoNxt",\
    60:"IPv6-Opts", 62:"CFTP", 64:"SAT-EXPAK", 65:"KRYPTOLAN", 66:"RVD", 67:"IPPC", 69:"SAT-MON",\
    70:"VISA", 71:"IPCV", 72:"CPNX", 73:"CPHB", 74:"WSN", 75:"PVP", 76:"BR-SAT-MON", 77:"SUN-ND", 78:"WB-MON", 79:"WB-EXPAK",\
    80:"ISO-IP", 81:"VMTP", 82:"SECURE-VMTP", 83:"VINES", 84:"TTP", 84:"IPTM", 85:"NSFNET-IGP", 86:"DGP", 87:"TCF", 88:"EIGRP", 89:"OSPFIGP",\
    90:"Sprite-RPC", 91:"LARP", 92:"MTP", 93:"AX.25", 94:"IPIP", 96:"SCC-SP", 97:"ETHERIP", 98:"ENCAP",\
    100:"GMTP", 101:"IFMP", 102:"PNNI", 103:"PIM", 104:"ARIS", 105:"SCPS", 106:"QNX", 107:"A/N", 108:"IPComp", 109:"SNP",\
    110:"Compaq-Peer", 111:"IPX-in-IP", 112:"VRRP", 113:"PGM", 115:"L2TP", 116:"DDX", 117:"IATP", 118:"STP", 119:"SRP",\
    120:"UTI", 121:"SMP", 123:"PTP", 125:"FIRE", 126:"CRTP", 127:"CRUDP", 128:"SSCOPMCE", 129:"IPLT",\
    130:"SPS", 131:"PIPE", 132:"SCTP", 133:"FC", 134:"RSVP-E2E-IGNORE", 136:"UDPLite", 137:"MPLS-in-IP", 138:"manet", 139:"HIP",\
    140:"Shim6", 141:"WESP", 142:"ROHC", 255:"Reserved"\
    }


def usage():
    print("Output Format")
    print("Event ID\tEvent Time\tSource IP:Source Port => Destination IP:Destination Port\tProtocol\tPriority\n")
    print("If you used verbose mode(-v)\n")
    print("Siganature Message\tSignature Class\tSignature Reference(URL)")
    print("Classification Name\tDescription\t%s\n")

    #print("[*] Example")
    #TODO


def parse_argv():
    parser = argparse.ArgumentParser(description='Snort Unified2 Log Parser')
    parser.add_argument('logfile')
    parser.add_argument("-g", "--gen-map", type=str, default="gen-msg.map", help="Snort gen-msg.map file. Default ./gen-msg.map")
    parser.add_argument("-s", "--sid-map", type=str, default="sid-msg.map", help="Snort sid-msg.map file. Default ./sid-map.map")
    parser.add_argument("-c", "--classfication", type=str, default="classification.config", help="Snort classification.config file. Default ./classification.config")
    parser.add_argument("-p", "--priority", type=int, default="0", help="Priority")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    args = parser.parse_args()
    usage()
    return args


def epoch_to_datetime(epoch):
    """
    Unix Epoch Time Convert to DateTime
    Return format 2012-10-10 21:12:17
    """
    return datetime.datetime(*time.localtime(epoch)[:6])

def main():
    args = parse_argv()


    sigmap = maps.SignatureMap()
    sigmap.load_generator_map(open(args.gen_map))
    sigmap.load_signature_map(open(args.sid_map))

    classmap = maps.ClassificationMap()
    classmap.load_from_file(open(args.classfication))

    reader = unified2.SpoolEventReader(os.path.split(args.logfile)[0], os.path.split(args.logfile)[1])

    for event in reader:
        event_time = epoch_to_datetime(event["event-second"])
        event_id = event["event-id"]
        sig_id = event["signature-id"]
        gen_id = event["generator-id"]
        src_ip = event["source-ip"]
        dst_ip = event["destination-ip"]
        src_port = event["sport-itype"]
        dst_port = event["dport-icode"]
        protocol = PROTOCOLS.get(event["protocol"])
        priority = event["priority"]
        class_id = event["classification-id"]

        sigmap_info = sigmap.get(gen_id, sig_id)
        class_info = classmap.get(class_id)

        sigmap_class = sigmap_info.get("classification")
        sigmap_msg = sigmap_info.get("msg")
        sigmap_ref = sigmap_info.get("ref")

        class_name = class_info["name"]
        class_description = class_info["description"]

        if args.priority <= priority:
            print("%d\t%s\t%s:%d => %s:%d\t%s\t%d" % (event_id, event_time, src_ip, src_port, dst_ip, dst_port, protocol, priority) )
            if args.verbose:
                print("\t%s\t%s\t%s" % (sigmap_msg, sigmap_class, sigmap_ref))
                print("\t%s\t%s" % (class_name, class_description))


if __name__ == "__main__":
    main()



