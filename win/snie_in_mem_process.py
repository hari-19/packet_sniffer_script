# -*- coding: utf-8 -*-
"""
@author: hari-19
"""
from rich.pretty import pprint
import csv
from snie_win_pkt_sniff import snie_get_udppayloadlen, snie_get_udp_prot_info, snie_get_otherpayloadlen, snie_get_other_prot_info, snie_get_tcppayloadlen, snie_get_tls_proto_info, snie_update_tls_info, snie_get_tcp_prot_info, snie_get_quic_prot_info, snie_read_raw_pkts, snie_sniff_packets

header_index = {
    "Time": 0,
    "TLS version": 1,
    "SNI": 2,
    "Source IP address": 3,
    "Destination IP address": 4,
    "Source port": 5,
    "Destination Port": 6,
    "Protocol": 7,
    "Downloaded Data size (bytes)": 8,
    "TLS session duration (s)": 9,
    "Foreground/Background": 10,
    "SSL Certificate information": 11
}

tcp_count = 0
udp_count = 0
quic_count = 0

header = ["Time", "TLS version", "SNI", "Source IP address", "Destination IP address", "Source port",
          "Destination Port", "Protocol", "Downloaded Data size (bytes)", "TLS session duration (s)",
          "Foreground/Background", "SSL Certificate information"]

csv_header = {"Time": "Time", "TLS version": "TLS version", "SNI": "SNI", "Source IP address": "Source IP address",
              "Destination IP address": "Destination IP address", "Source port": "Source port",
              "Destination Port": "Destination Port", "Protocol": "Protocol",
              "Downloaded Data size (bytes)": "Downloaded Data size (bytes)",
              "TLS session duration (s)": "TLS session duration (s)",
              "Foreground/Background": "Foreground/Background",
              "SSL Certificate information": "SSL Certificate information"}


processed_data = {}

def generate_tcp_dict_key(packet):
    return "TCP" + "-" + str(packet['ip'].src) + "-" +str(packet['ip'].dst) + "-" +str(packet['tcp'].srcport) + "-" + str(packet['tcp'].dstport)

def generate_udp_dict_key(packet):
    return "UDP" + "-" + str(packet['ip'].src) + "-" +str(packet['ip'].dst) + "-" +str(packet['udp'].srcport) + "-" + str(packet['udp'].dstport)

def generate_quic_dict_key(saddr, daddr, sport, dport):
    return "QUIC" + "-" + str(saddr) + "-" + str(daddr) + "-" + str(sport) + "-" + str(dport)

def generate_other_dict_key(packet):
    return str(packet['ip'].proto) + "-" + str(packet['ip'].src) + "-" + str(packet['ip'].dst)
            

def snie_update_udp_data(dreader, packet):
    if not 'udp' in packet:
        return
    
    if generate_udp_dict_key(packet) in processed_data.keys():
        row = generate_row_dict(processed_data[generate_udp_dict_key(packet)])
        osize = int(row["Downloaded Data size (bytes)"])
        psize = snie_get_udppayloadlen(packet)
        dsize = osize + psize
        row['Downloaded Data size (bytes)'] = dsize
        processed_data[generate_udp_dict_key(packet)] = generate_list_from_dict(row)
    else:
        sni_info = snie_get_udp_prot_info(packet)
        processed_data[generate_udp_dict_key(packet)] = sni_info

def snie_handle_udp_packet(fp, dreader, packet):
    snie_update_udp_data(dreader, packet)
    return packet

def snie_update_other_data(dreader, packet):
    if generate_other_dict_key(packet) in processed_data.keys():
        row = generate_row_dict(processed_data[generate_other_dict_key(packet)])
        osize = int(row["Downloaded Data size (bytes)"])
        psize = snie_get_otherpayloadlen(packet)
        dsize = osize + psize
        row['Downloaded Data size (bytes)'] = dsize
        processed_data[generate_other_dict_key(packet)] = generate_list_from_dict(row)
    else:
        sni_info = snie_get_other_prot_info(packet)
        processed_data[generate_other_dict_key(packet)] = sni_info

def snie_handle_other_packet(fp, dreader, packet):
    snie_update_other_data(dreader, packet)
    return packet


def snie_update_tcp_data(fp, packet):
    if not 'tcp' in packet:
        return
    
    if generate_tcp_dict_key(packet) in processed_data.keys():
        row = generate_row_dict(processed_data[generate_tcp_dict_key(packet)])
        osize = int(row["Downloaded Data size (bytes)"])
        psize = snie_get_tcppayloadlen(packet)
        dsize = osize + psize
        row['Downloaded Data size (bytes)'] = dsize
        # Update TLS duration
        ti = float(row['Time'])
        te = float(packet.sniff_timestamp)
        tdiff = te - ti

        row["TLS session duration (s)"] = tdiff
        # Update TLS duration
        sni_info = ["NA", "NA", ["NA"]]
        sni_info = snie_get_tls_proto_info(fp, packet, sni_info)
        if sni_info[1] != "NA":
            row = snie_update_tls_info(row, sni_info)
        processed_data[generate_tcp_dict_key(packet)] = generate_list_from_dict(row)
    else:
        sni_info = snie_get_tcp_prot_info(packet)
        sni_info = snie_get_tls_proto_info(fp, packet, sni_info)
        processed_data[generate_tcp_dict_key(packet)] = sni_info

def generate_row_dict(processed_packet_list):
    row_dict = {}
    for key in header_index.keys():
        row_dict[key] = processed_packet_list[header_index[key]]

    return row_dict

def generate_list_from_dict(processed_packet_dict):
    row_list = []
    for key in header_index.keys():
        row_list.append(processed_packet_dict[key])

    return row_list

def snie_handle_tcp(fp, packet):
    snie_update_tcp_data(fp, packet)
    return packet


def snie_record_quic_info(saddr, daddr, sport, dport, sni, len, tstamp, tls_version):
    if generate_quic_dict_key(saddr, daddr, sport, dport) in processed_data.keys():
        row = generate_row_dict(processed_data[generate_quic_dict_key(saddr, daddr, sport, dport)])
        osize = int(row["Downloaded Data size (bytes)"])
        psize = len*8
        dsize = osize + psize
        row['Downloaded Data size (bytes)'] = str(dsize)
        # Update data size
        # Update TLS duration
        ti = float(row['Time'])
        te = float(tstamp)
        tdiff = te - ti
        # tdiff = tdiff.total_seconds()
        row["TLS session duration (s)"] = tdiff
        processed_data[generate_quic_dict_key(saddr, daddr, sport, dport)] = generate_list_from_dict(row)
    else:
        sni_info = snie_get_quic_prot_info(saddr, daddr, sport, dport, sni, len*8, tstamp, tls_version)
        processed_data[generate_quic_dict_key(saddr, daddr, sport, dport)] = sni_info

def snie_process_raw_packets(raw_pkts, MAX_PKT_COUNT):
    sd_pkts = []
    fp = open('./Output_data/sni.txt', 'a', newline='')
    pkt_count = 0
    global tcp_count
    global udp_count
    global quic_count

    # Filter TLS packets nd get SNI
    for packet in raw_pkts:
        if 'ip' in packet:
            try:
                if 'quic' in packet:  # QUIC packet
                    from snie_win_quic import sne_quic_extract_pkt_info
                    saddr, daddr, sport, dport, sni, qlen, tstamp, tls_version = sne_quic_extract_pkt_info(packet)
                    snie_record_quic_info(saddr, daddr, sport, dport, sni, qlen, tstamp, tls_version)
                    quic_count += 1
                elif 'tcp' in packet:
                    x = snie_handle_tcp(fp, packet)
                    tcp_count += 1
                elif 'udp' in packet:  # UDP packet
                    x = snie_handle_udp_packet(fp, None, packet)
                    udp_count += 1
                else:
                    x = snie_handle_other_packet(fp, None, packet)
            except KeyboardInterrupt:
                print("Execution interrupted")
                exit(0)
            pkt_count += 1
            #print("[+] Number of packets processed : TCP = " + str(tcp_count) + "  UDP = " + str(udp_count) + \
                  #"  QUIC = " + str(quic_count) + "  Total = " + str(pkt_count), end = "\r")
        if MAX_PKT_COUNT != "NA" and pkt_count >= MAX_PKT_COUNT:
            break
    fp.close()
    # print("\nTCP : " + str(tcp_count) + "  UDP : " + str(udp_count) + "\n")
    return sd_pkts


def snie_sanitize_data_list(data_list):
    for line in data_list:
        if line == []:
            continue

        if line[2] != "NA":
            sni = line[2]
            sni = sni.replace(" ", "")
            snil = list(sni.replace(",", ""))
            sni = ""
            for item in snil:
                if item != ",":
                    sni += item
            line[2] = sni


def write_to_csv(data_list, fname):
    with open(fname, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(header_index.keys())
        for line in data_list:
            if line == []:
                continue
            writer.writerow(line)

def snie_process_packets(MAX_PKT_COUNT, STO, fname):
    itr = 1
    while itr == 1:
        itr += 1
        raw_pkts = snie_read_raw_pkts(STO, fname)
        if raw_pkts is None:
            print("Too few packets to sniff")
            break
        try:
            snie_process_raw_packets(raw_pkts, MAX_PKT_COUNT)
        except (KeyboardInterrupt, SystemExit):
            break
    processed_data_list = []

    for key in processed_data:
        processed_data_list.append(processed_data[key])       

    snie_sanitize_data_list(processed_data_list)

    write_to_csv(processed_data_list, './Output_data/sni.csv')
    return

def snie_record_and_process_pkts(command, fname, STO=30):
    global itime
    MAX_PKT_COUNT = "NA" # "NA : no bound"
    if fname != None:
        snie_process_packets(MAX_PKT_COUNT, STO, fname)
    elif command == "ALL":
        snie_sniff_packets(STO)
        snie_process_packets(MAX_PKT_COUNT, STO)
    else:
      print("Unknown command : Use S/A/ALL")