#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
from time import sleep
from multiprocessing import Process
import json
from flask import Flask, request, render_template

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '/home/sinet/P4/tutorials/utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2

app = Flask(__name__, static_url_path='')

def write_mapping_rules(p4info_helper, ingress_sw, egress_sw, src_sinet_length, 
                        src_sinet_addr, dst_sinet_length, dst_sinet_addr, 
                        dst_mac_addr2, dst_mac_addr1, ip_dst_addr, sinet_dst_addr):
    # mapping ingress rule
    table_entry = p4info_helper.buildTableEntry(
        table_name="ipv4_sinet",
        match_fields={
            "hdr.ipv4.dstAddr": (ip_dst_addr, 32)
        },
        action_name="ipv4_sinet_forward",
        action_params={
            "src_sinet_length": src_sinet_length,
            "src_sinet_addr": src_sinet_addr,
            "dst_sinet_length": dst_sinet_length,
            "dst_sinet_addr": dst_sinet_addr,
            "dst_mac_addr": dst_mac_addr2,
            "port": SWITCH_TO_SWITCH_PORT
        })
    ingress_sw.WriteTableEntry(table_entry)
    print "Installed the mapping ingress rules on %s" % ingress_sw.name

    # mapping egress rule
    table_entry = p4info_helper.buildTableEntry(
        table_name="sinet_ipv4",
        match_fields={
            "meta.sinetAddr_dst": (sinet_dst_addr, 256)
        },
        action_name="sinet_ipv4_forward",
        action_params={
            "dstAddr": dst_mac_addr1,
            "port": SWITCH_TO_HOST_PORT
        })
    egress_sw.WriteTableEntry(table_entry)
    print "Installed the mapping egress rules on %s" % egress_sw.name


def read_table_rules(p4info_helper, sw):
    print '\n----- Reading tables rules for %s -----' % sw.name
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            print entry
            print '-----'

def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:9090',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:9091',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s1"
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s2"

        # Write the rules that mapping traffic from h1 to h2
        write_mapping_rules(p4info_helper, ingress_sw=s1, egress_sw=s2, 
                            src_sinet_length=63,
                            src_sinet_addr="0xff00ff00ff00ff00000000000000000000000000000000000000000000000000", 
                            dst_sinet_length=63, 
                            dst_sinet_addr="0x0f0f0f0f0f0f0f0f000000000000000000000000000000000000000000000000",
                            dst_mac_addr2="00:00:00:02:02:00", 
                            dst_mac_addr1="00:00:00:00:01:01", 
                            ip_dst_addr="10.0.2.2", 
                            sinet_dst_addr="0xff00ff00ff00ff00000000000000000000000000000000000000000000000000")

        # Write the rules that mapping traffic from h2 to h1
        write_mapping_rules(p4info_helper, ingress_sw=s2, egress_sw=s1, 
                            src_sinet_length=63,
                            src_sinet_addr="0x0f0f0f0f0f0f0f0f000000000000000000000000000000000000000000000000",
                            dst_sinet_length=63, 
                            dst_sinet_addr="0xff00ff00ff00ff00000000000000000000000000000000000000000000000000",
                            dst_mac_addr2="00:00:00:01:01:00",
                            dst_mac_addr1="00:00:00:00:02:02",
                            ip_dst_addr="10.0.1.1",
                            sinet_dst_addr="0x0f0f0f0f0f0f0f0f000000000000000000000000000000000000000000000000")

        # Print the mapping tables every 2 seconds
        #while True:
        #    sleep(2)
        #    print '\n----- Reading each switch tables -----'
        #    read_table_rules(p4info_helper, s1)
        #    read_table_rules(p4info_helper, s2)

    #except KeyboardInterrupt:
    #    print " Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

def update_mapping_entries(host_ip,flow_id):
    file_data = ''
    try:
        with open ('/home/sinet/liugang/VLI/mapping.entry','r') as f0:
            for line in f0:
                tmp=line.replace('\n','').split("%")
                if tmp[0].decode("utf-8") == host_ip:
                    if tmp[3] == ' ':
                        tmp[3] = flow_id
                    else:
                        tmp[3] = tmp[3] + ',' +  flow_id
                    line = tmp[0] + '%' + tmp[1] + '%' + tmp[2] + '%' + tmp[3]
                file_data += line
        with open ('/home/sinet/liugang/VLI/mapping.entry','w') as f1:
            f1.write(file_data)
        return True
    except:
        import traceback
        traceback.print_exc()
        return None

@app.route('/', methods=['GET'])
def get_mapping_entries():
    mapping_entries = {}
    try:
        with open ('/home/sinet/liugang/VLI/mapping.entry','r') as f0:
            next(f0)
            for line in f0:
                tmp=line.replace('\n','').split("%")
                mapping_entries[tmp[0]] = tmp[1]
        return str(mapping_entries)
    except:
        import traceback
        traceback.print_exc()
        return None

@app.route('/', methods=['PUT'])
def add_mapping_entries():
    request_data = json.loads(request.get_data())
    router_id = request_data['router_id']
    src_ip = request_data['src_ip'] + '/32'
    flow_id = str(int(time.time()*1000))
    with open('/home/sinet/liugang/VLI/mapping.entry','a') as f:
        f.write(request_data['src_ip']+'%'+request_data['router_id']+'%'+'\n')
    return "Add a mapping entiry successfully."

@app.route('/', methods=['DELETE'])
def delete_mapping_entries():
    try:
        file_data = ''
        src_ip = json.loads(request.get_data())['src_ip']
        with open ('/home/sinet/liugang/VLI/mapping.entry','r') as f0:
            for line in f0:
                tmp=line.replace('\n','').split("%")
                if tmp[0].decode("utf-8") == src_ip:
                    odl.delete_flow(tmp[1],tmp[2])
                else:
                    file_data += line
        with open ('/home/sinet/liugang/VLI/mapping.entry','w') as f1:
            f1.write(file_data)
        return "Delete a mapping entiry successfully."
    except:
        import traceback
        LOG.error("Delete a mapping entiry unsuccessfully.")
        traceback.print_exc()
        return None

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/advanced_tunnel.p4info')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/advanced_tunnel.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)
    # subprocess to support the API
    #p=Process(target=app.run, args=('127.0.0.1',40000))
    #p.start()
    # main process to support p4runtime
    main(args.p4info, args.bmv2_json)
