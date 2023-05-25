import pyshark

def decrypt_payload(dcid, payload_string,  packet_number):
    import hkdf
    from binascii import unhexlify, hexlify
    import hashlib

    initial_salt = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"
    dcid = dcid.replace(":","")
    payload_string = payload_string.replace(":","")
    # dcid = "8394c8f03e515708"
    
    client_in = "00200f746c73313320636c69656e7420696e00"
    quic_key = "00100e746c7331332071756963206b657900"
    quic_iv = "000c0d746c733133207175696320697600"
    quic_hp = "00100d746c733133207175696320687000"

    initial_secret = hkdf.hkdf_extract(unhexlify(initial_salt), unhexlify(dcid), hash=hashlib.sha256)
    client_initial_secret = hkdf.hkdf_expand(initial_secret, unhexlify(client_in), 32, hash=hashlib.sha256)
    
    key = hkdf.hkdf_expand(client_initial_secret, unhexlify(quic_key), 16, hash=hashlib.sha256)
    iv = hkdf.hkdf_expand(client_initial_secret, unhexlify(quic_iv), 12, hash=hashlib.sha256)
    hp = hkdf.hkdf_expand(client_initial_secret, unhexlify(quic_hp), 16, hash=hashlib.sha256)
    iv = hexlify(iv)
    nonce = packet_number ^ int(iv,16)
    nonce = hex(nonce)[2:]
    nonce = unhexlify(nonce)
    # print(len(payload_string))
    tag = unhexlify(payload_string[-32:])
    payload_string = payload_string[:-32]


    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=None)
    
    decryptor = cipher.decryptor()

    final = decryptor.update(unhexlify(payload_string)) # + decryptor.finalize()
    print(len(final))
    return final


def sne_quic_extract_pkt_info(packet):
    if 'quic' not in packet:
        return None
    print(packet['quic'].long_packet_type)
    if packet['quic'].long_packet_type != '0': # 0 is for Initial Packet frame
        return None
    
    dcid = packet['quic'].dcid
    payload_string = packet['quic'].payload
    packet_number = packet['quic'].packet_number
    print(packet_number)
    decrypt_payload(dcid, payload_string, int(packet_number))

    

def sne_quic_extract_pkt_info_old(packet):
    tls_extension_version = 0x0a
    tls_version = 0x0a
    llayer = dir(packet['quic'])

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


    if tls_version != 'NA':
        final_version = max(int(str(tls_extension_version),16),int(str(tls_version),16))
        final_version = str(hex(final_version));
        final_version = f"{final_version[:2]}0{final_version[2:]}"
        tls_version = final_version
    return saddr, daddr, sport, dport, sni, qlen, tstamp, tls_version


def snie_quic(pcap_file, lfile):
    import pyshark

    pcap_data = pyshark.FileCapture(pcap_file)
    fp = open(lfile, "w")
    fp.close()

    pcount = 0
    quic_pinfo = []
    for packet in pcap_data:
        for layer in packet:
            if layer.layer_name == 'quic':
                fp = open(lfile, "a")
                saddr, daddr, sport, dport, sni = sne_quic_extract_pkt_info(packet, layer)
                quic_pinfo.append([saddr, daddr, sport, dport, sni])
                print("Extracted values : " + str(quic_pinfo))
                output_data = "QUIC packet detected : " + str(layer)
                #print(output_data)
                fp.write(str(packet))
                fp.write("\n END OF PACKET \n")
                fp.close()
                break
        pcount += 1
        print("Packets processed = ", str(pcount), end="\r")


if __name__ == '__main__':
    pcap_file = './Input_data/pkts_30.pcap'
    pcap_data = pyshark.FileCapture(pcap_file)
    sne_quic_extract_pkt_info(pcap_data[12])
