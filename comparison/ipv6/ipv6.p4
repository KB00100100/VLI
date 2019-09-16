/* -*- P4_16 -*- */

#include <core.p4>
#include <v1model.p4>

//the ether_type of ipv4 in ipv6
const bit<16> TYPE_IPv6 = 0x1212;
const bit<16> TYPE_IPv4 = 0x0800;


/*************************************************************************
 *********************** H E A D E R S ***********************************
*************************************************************************/
//definitions of some global type.
typedef bit<9> egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<128> ipv6Addr_t;


//the template of ethernet header.
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

//the template of ipv6 header.
header ipv6_t {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_length;
    bit<8> next_header;
    bit<8> hop_limit;
    bit<128> srcAddr;
    bit<128> dstAddr;
}

//the template of ipv4 header
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>  totalLen;
    bit<16>  identification;
    bit<3>    flags;
    bit<13>  fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>  hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}


struct metadata {
    /* empty */
}

//instantiate the headers.
struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    ipv6_t ipv6;
}


/*************************************************************************
************************** P A R S E R ***********************************
*************************************************************************/

parser BlackBoxParser(packet_in packet,
                      out headers hdr,
                      inout metadata meta,
                      inout standard_metadata_t standard_metadata) {

    state start {
        transition select(standard_metadata.ingress_port) {
            default: parse_ethernet;
        }
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPv6: parse_ipv6;
            TYPE_IPv4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.next_header) {
            0x88: parse_ipv4;
            default: accept;
        }
    }
    
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

/*************************************************************************
**************** C H E C K S U M V E R I F I C A T I O N *****************
*************************************************************************/
control BlackBoxVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply { }
}


/*************************************************************************
******************* I N G R E S S P R O C E S S I N G ********************
*************************************************************************/
control BlackBoxIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    action drop() {
        mark_to_drop();
    }

    //para: dst_mac_addr, src_ipv6_length, src_ipv6_addr, dst_ipv6_length, dst_ipv6_addr, port(output)
    action ipv4_ipv6_forward(macAddr_t dst_mac_addr, ipv6Addr_t src_ipv6_addr, ipv6Addr_t dst_ipv6_addr, egressSpec_t port) {
        hdr.ipv6.setValid();
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dst_mac_addr;
        hdr.ipv6.srcAddr = src_ipv6_addr;
        hdr.ipv6.dstAddr = dst_ipv6_addr;
        hdr.ipv6.hop_limit = hdr.ipv4.ttl - 1;
    }

    //para:
    action ipv6_ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_ipv6 {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_ipv6_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

   table ipv6_ipv4 {
        key = {
            hdr.ipv6.dstAddr: lpm;
        }
        actions = {
            ipv6_ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply{
        //ipv4 or ipv6
        if(!hdr.ipv6.isValid()) {
            //set nextheader: ipv4
            hdr.ipv6.next_header = 0x88;
            hdr.ethernet.etherType = TYPE_IPv6;
            ipv4_ipv6.apply();
        }
        else{
            hdr.ethernet.etherType = TYPE_IPv4;
            ipv6_ipv4.apply();
            hdr.ipv6.setInvalid();
        }
    }
}

/*************************************************************************
******************* E G R E S S P R O C E S S I N G **********************
*************************************************************************/

control BlackBoxEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply {
            
    }
}

/*************************************************************************
***************** C H E C K S U M C O M P U T A T I O N ******************
*************************************************************************/

control BlackBoxComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
                { hdr.ipv4.version,
                  hdr.ipv4.ihl,
                  hdr.ipv4.diffserv,
                  hdr.ipv4.totalLen,
                  hdr.ipv4.identification,
                  hdr.ipv4.flags,
                  hdr.ipv4.fragOffset,
                  hdr.ipv4.ttl,
                  hdr.ipv4.protocol,
                  hdr.ipv4.srcAddr,
                  hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
*********************** D E P A R S E R *******************************
*************************************************************************/

control BlackBoxDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
*********************** S W I T C H *******************************
*************************************************************************/
V1Switch(
BlackBoxParser(),
BlackBoxVerifyChecksum(),
BlackBoxIngress(),
BlackBoxEgress(),
BlackBoxComputeChecksum(),
BlackBoxDeparser()
) main;
