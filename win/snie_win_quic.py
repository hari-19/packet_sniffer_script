
def sne_quic_extract_pkt_info(packet):
    tls_extension_version = 0x0a
    tls_version = 0x0a
    llayer = dir(packet['quic'])
    # print("QUIC layer info : " + str(llayer))
    sni = 'NA'
    tls_version = 'NA'
    qlen = int(packet['quic'].packet_length)
    tstamp = float(packet.sniff_timestamp)
    if 'ip' in packet:
        saddr = packet['ip'].src
        daddr = packet['ip'].dst
    else:
        saddr = daddr = 0
    if 'udp' in packet:
        sport = packet['udp'].srcport
        dport = packet['udp'].dstport
    else:
        sport = dport = 0

    if "tls_handshake_extensions_supported_version" in llayer:
        tls_extension_version = packet['quic'].tls_handshake_extensions_supported_version
    if "tls_handshake_version" in llayer:
        #print("QUIC packet : " + str(dir(packet['quic'])))
        #exit(0)
        tls_version = packet['quic'].tls_handshake_version
    if 'tls_handshake_extensions_server_name' in llayer:
        sni = packet['quic'].tls_handshake_extensions_server_name
    # else:
    #    print("SNI not present")
    # print("QUIC SNI = " + str(sni))
    #print(tls_extension_version)
    #print(f"old{tls_version}")
    if tls_version != 'NA':
        final_version = max(int(str(tls_extension_version),16),int(str(tls_version),16))
        final_version = str(hex(final_version));
        final_version = f"{final_version[:2]}0{final_version[2:]}"
        tls_version = final_version
    return saddr, daddr, sport, dport, sni, qlen, tstamp, tls_version


def snie_quic(pcap_file, lfile):
    import pyshark
    import csv

    pcap_data = pyshark.FileCapture(pcap_file)
    fp = open(lfile, "w")
    fp.close()

    pcount = 0
    quic_pinfo = []
    f = open(lfile, "w")
    writer = csv.writer(f)
    writer.writerow(['Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'SNI', 'Packet Length', 'Timestamp', 'TLS Version'])

    for packet in pcap_data:
        for layer in packet:
            if layer.layer_name == 'quic':
                fp = open(lfile, "a")
                saddr, daddr, sport, dport, sni, qlen, tstamp, tls_version = sne_quic_extract_pkt_info(packet)
                quic_pinfo.append([saddr, daddr, sport, dport, sni, qlen, tstamp, tls_version])
                # print("Extracted values : " + str(quic_pinfo))
                # output_data = "QUIC packet detected : " + str(layer)
                #print(output_data)
                # fp.write(str(packet))
                writer.writerow([saddr, daddr, sport, dport, sni, qlen, tstamp, tls_version])
                fp.write("\n END OF PACKET \n")
                fp.close()
                break
        pcount += 1
        print("Packets processed = ", str(pcount), end="\r")


if __name__ == '__main__':
    pcap_file = './cap2.pcapng'
    lfile = "./Output_data/plog.txt"
    snie_quic(pcap_file, lfile)