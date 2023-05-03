#!/usr/bin/env python3

import json


#forward pkt is client(src) to server(dst)

client_port = '36916'
server_port = '6121'


all_fpkts = []

def handle_duplicates(dct):
    result = {}
    for key, value in dct:
        if key in result:
            if isinstance(result[key], list):
                result[key].append(value)
            else:
                result[key] = [result[key], value]
        else:
            result[key] = value
    return result


def forward(src_port, dst_port):
    if src_port == client_port and dst_port == server_port:
        return True
    else:
        return False


#pkt_layers = packet["_source"]["layers"]
def get_fpkt_num(pkt_layers):
    if 'quic.packet_number' in pkt_layers['quic']:
        quic_pkt_num = pkt_layers['quic']['quic.packet_number']
    elif 'quic.packet_number' in pkt_layers['quic']['quic.short']:
        quic_pkt_num = pkt_layers['quic']['quic.short']['quic.packet_number']
    return quic_pkt_num


def get_ack_frame(quic_pkt):
    print(quic_pkt)
    ack_frame = {}
    if 'quic.frame' in quic_pkt:
        frame = quic_pkt['quic.frame']
        frame_type = frame['quic.frame_type']
        if frame_type == 2 or frame_type == 3:
            ack_frame = frame
    
    return ack_frame


def main():
    with open('decrypted_dump.json') as openfile:
        #json_object = json.load(openfile)
        json_object = json.load(openfile, object_pairs_hook=handle_duplicates)


    for packet in json_object:
        a = packet["_source"]["layers"]
        src_port = a['udp']['udp.srcport']
        dst_port = a['udp']['udp.dstport']

        timestamp = a['frame']["frame.time_epoch"]

        this_dict = {}

        if forward(src_port, dst_port) == True:
            this_dict['fpkt_num'] = get_fpkt_num(a)
            this_dict['fpkt_tstamp'] = timestamp
            all_fpkts.append(this_dict)
        else: ##pkt is backward
            quic_frame = a['quic']
            
            print("#########################################")
            print(quic_frame)

            continue

            ack_frame = get_ack_frame(quic_frame)
            #if len(ack_frame) != 0:
            #    print(ack_frame)
    


    return




if __name__ == "__main__":
    main()
