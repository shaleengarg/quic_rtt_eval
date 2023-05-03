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


#quic_frame = quic['quic.frame']
def get_ack_info(quic_frame):
    ack_list = []
    if isinstance(quic_frame, list):
        for each_frame in quic_frame:
            ack_dict = {}
            if 'quic.ack.largest_acknowledged' in each_frame:
                largest_acked = each_frame['quic.ack.largest_acknowledged']
                ack_delay = each_frame['quic.ack.ack_delay']
                ack_dict['largest_acked'] = largest_acked
                ack_dict['ack_delay'] = ack_delay
                ack_list.append(ack_dict);
    elif isinstance(quic_frame, dict):
        ack_dict = {}
        if 'quic.ack.largest_acknowledged' in quic_frame:
            largest_acked = quic_frame['quic.ack.largest_acknowledged']
            ack_delay = quic_frame['quic.ack.ack_delay']
            ack_dict['largest_acked'] = largest_acked
            ack_dict['ack_delay'] = ack_delay
            ack_list.append(ack_dict);

    #print(ack_list)
    return ack_list


#quic_frame = a['quic']
def get_ack_frame(quic_pkt):
    ack_frame = []

    if isinstance(quic_pkt, list): 
        for quic in quic_pkt:
            quic_frame = quic['quic.frame']
            ack_frame.extend(get_ack_info(quic_frame))

    elif isinstance(quic_pkt, dict):
        quic_frame = quic_pkt['quic.frame']
        ack_frame.extend(get_ack_info(quic_frame))
    else:
        print("Fatal error: neither a list nor a dict")

    return ack_frame


def calculate_rtt(fpkt_tstamp, ack_tstamp):
    ft = float(fpkt_tstamp)
    at = float(ack_tstamp)
    return (at - ft)

def map_ack_frame_to_forward(all_fpkts, ack_frame, timestamp):
    for ack in ack_frame:
        largest_ack = ack['largest_acked'];
        ack_delay = ack['ack_delay']
        for fpkt in all_fpkts:
            fpkt_num = fpkt['fpkt_num']
            fpkt_tstamp = fpkt['fpkt_tstamp']
            if(fpkt_num == largest_ack):
                fpkt['ack_tstamp'] = timestamp
                fpkt['ack_delay'] = ack_delay
                fpkt['calculated_rtt'] = calculate_rtt(fpkt_tstamp, timestamp)
    return

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
            ack_frame = get_ack_frame(quic_frame)
            if len(ack_frame) != 0:
                map_ack_frame_to_forward(all_fpkts, ack_frame, timestamp)

    print(all_fpkts)

    return




if __name__ == "__main__":
    main()
