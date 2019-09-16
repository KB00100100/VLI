/* -*- P4_16 -*- */

#include <core.p4>
#include <v1model.p4>

//the ether_type of SINET
const bit<16> TYPE_SINET = 0x9999;
const bit<16> TYPE_IPv4 = 0x0800;
const bit<9> CPU_PORT = 255;

register<bit<48>>(256) int_queue;

/*************************************************************************
 *********************** H E A D E R S ***********************************
*************************************************************************/
//definitions of some global type.
typedef bit<9> egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<8> sinetAddrLength_t;
typedef bit<256> sinetAddr_t;

@controller_header("packet_in")
header packet_in_header_t {
    bit<9> ingress_port;
}

@controller_header("packet_out")
header packet_out_header_t {
    bit<9> egress_port;
}

//the template of ethernet header.
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

//the template of sinet header.
header sinet_t {
    bit<4> version;
    bit<8> slicing_id;
    bit<20> flow_label;
    bit<16> payload_length;
    bit<8> next_header;
    bit<8> srcAddr_length;
    bit<8> dstAddr_length;
    bit<8> hop_limit;
    bit<16> extra_state_info;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

//the template of sinet extend header --- srcAddr graft 0x80
header sinet_extend_src_graft_t {
    bit<8> next_header;
    bit<120> srcAddr;
}

//the template of sinet extend header --- dstAddr graft 0x90
header sinet_extend_dst_graft_t {
    bit<8> next_header;
    bit<120> dstAddr;
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

//the INT header to measure some network params
header int_sinet_t {
    bit<32> switch_id;
    bit<48> global_ingress_timestamp;
    bit<48> global_egress_timestamp;
    bit<32> qdepth;
}

struct metadata {
    /* empty */
    bit<256> sinetAddr_src;
    bit<256> sinetAddr_dst;
}

//instantiate the headers.
struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    //ipv6_t ipv6;
    sinet_t sinet;
    sinet_extend_src_graft_t sinet_extend_src_graft0; 
    sinet_extend_src_graft_t sinet_extend_src_graft1;
    sinet_extend_dst_graft_t sinet_extend_dst_graft0;
    sinet_extend_dst_graft_t sinet_extend_dst_graft1;
    int_sinet_t int_sinet1;
    int_sinet_t int_sinet2;
    packet_out_header_t packet_out;
    packet_in_header_t packet_in;
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
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_SINET: parse_sinet;
            TYPE_IPv4: parse_ipv4;
            default: accept;
        }
    }

    state parse_sinet {
        packet.extract(hdr.sinet);
        //32 bits
        meta.sinetAddr_src[255:224] = hdr.sinet.srcAddr;
        meta.sinetAddr_dst[255:224] = hdr.sinet.dstAddr;
        transition select(hdr.sinet.next_header) {
            0x80: parse_sinet_extend_src_graft0;
            0x90: parse_sinet_extend_dst_graft0;
            0x88: parse_int_sinet1;
            default: accept;
        }
    }
    
    state parse_sinet_extend_src_graft0 {
        packet.extract(hdr.sinet_extend_src_graft0);
        //24 bits
        meta.sinetAddr_src[223:104] = hdr.sinet_extend_src_graft0.srcAddr;
        transition select(hdr.sinet_extend_src_graft0.next_header) {
            0x80: parse_sinet_extend_src_graft1;
            0x90: parse_sinet_extend_dst_graft0;
            default: accept;
        }
    }

    state parse_sinet_extend_src_graft1 {
        packet.extract(hdr.sinet_extend_src_graft1);
        //24 bits 
        meta.sinetAddr_src[103:0] = hdr.sinet_extend_src_graft1.srcAddr[119:16];
        transition select(hdr.sinet_extend_src_graft1.next_header) {
            0x88: parse_int_sinet1;
            0x90: parse_sinet_extend_dst_graft0;
            default: accept;
        }
    }

    state parse_sinet_extend_dst_graft0 {
        packet.extract(hdr.sinet_extend_dst_graft0);
        //24 bits
        meta.sinetAddr_dst[223:104] = hdr.sinet_extend_dst_graft0.dstAddr;
        transition select(hdr.sinet_extend_dst_graft0.next_header) {
            0x90: parse_sinet_extend_dst_graft1;
            0x88: parse_int_sinet1;
            default: accept;
        }
    }

    state parse_sinet_extend_dst_graft1 {
        packet.extract(hdr.sinet_extend_dst_graft1);
        //24 bits 
        meta.sinetAddr_dst[103:0] = hdr.sinet_extend_dst_graft1.dstAddr[119:16];
        transition select(hdr.sinet_extend_dst_graft1.next_header) {
            0x88: parse_int_sinet1;
            default: accept;
        }
    }

    state parse_int_sinet1 {
        packet.extract(hdr.int_sinet1);
        transition parse_int_sinet2;
    }

    state parse_int_sinet2 {
        packet.extract(hdr.int_sinet2);
        transition parse_ipv4;
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
    
    action send_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
        // Packets sent to the controller needs to be prepended with the
        // packet-in header. By setting it valid we make sure it will be
        // deparsed on the wire (see c_deparser).
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = standard_metadata.ingress_port;
    }

    //para: dst_mac_addr, src_sinet_length, src_sinet_addr, dst_sinet_length, dst_sinet_addr, port(output)
    action ipv4_sinet_forward(macAddr_t dst_mac_addr, sinetAddrLength_t src_sinet_length, sinetAddr_t src_sinet_addr, sinetAddrLength_t dst_sinet_length, sinetAddr_t dst_sinet_addr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dst_mac_addr;
        hdr.sinet.srcAddr_length = src_sinet_length;
        meta.sinetAddr_src = src_sinet_addr;
        hdr.sinet.dstAddr_length = dst_sinet_length;
        meta.sinetAddr_dst = dst_sinet_addr;
        hdr.sinet.hop_limit = hdr.ipv4.ttl - 1;
    }

    //para:
    action sinet_ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    //copy the packets to the INT analyzer
    action do_copy() {
        clone3(CloneType.I2E, (bit<32>)32w100, {standard_metadata});
    }

    table int_copy {
        actions = {
            do_copy;
        }
        size = 1024;
        default_action = do_copy();
    }

    table ipv4_sinet {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_sinet_forward;
            send_to_cpu;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

   table sinet_ipv4 {
        key = {
            meta.sinetAddr_dst: lpm;
        }
        actions = {
            sinet_ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply{
        //ipv4 or sinet
        if(!hdr.sinet.isValid()) {
            hdr.sinet.setValid();
            hdr.int_sinet1.setValid();
            hdr.int_sinet2.setValid();
            //set nextheader: ipv4
            //hdr.sinet.next_header = 0x88;
            hdr.ethernet.etherType = TYPE_SINET;
            ipv4_sinet.apply();
        }
        else{
            int_copy.apply();
            hdr.sinet.setInvalid();
            hdr.int_sinet1.setInvalid();
            hdr.int_sinet2.setInvalid();
            if(hdr.sinet_extend_src_graft0.isValid()) {
                hdr.sinet_extend_src_graft0.setInvalid();
            }
            if(hdr.sinet_extend_src_graft1.isValid()) {
                hdr.sinet_extend_src_graft1.setInvalid();
            }
            if(hdr.sinet_extend_dst_graft0.isValid()) {
                hdr.sinet_extend_dst_graft0.setInvalid();
            }
            if(hdr.sinet_extend_dst_graft1.isValid()) {
                hdr.sinet_extend_dst_graft1.setInvalid();
            }
            hdr.ethernet.etherType = TYPE_IPv4;
            sinet_ipv4.apply();
        }
    }
}

/*************************************************************************
******************* E G R E S S P R O C E S S I N G **********************
*************************************************************************/

control BlackBoxEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action add_int1(bit<32> switch_id) {
        hdr.int_sinet1.switch_id = switch_id;
        hdr.int_sinet1.global_ingress_timestamp = standard_metadata.ingress_global_timestamp;
        hdr.int_sinet1.global_egress_timestamp = standard_metadata.egress_global_timestamp;
        hdr.int_sinet1.qdepth = (bit<32>)standard_metadata.deq_qdepth;
        int_queue.write((bit<32>)standard_metadata.egress_port, (bit<48>)standard_metadata.enq_qdepth);
    }

    action add_int2(bit<32> switch_id) {
        hdr.int_sinet2.switch_id = switch_id;
        hdr.int_sinet2.global_ingress_timestamp = standard_metadata.ingress_global_timestamp;
        hdr.int_sinet2.global_egress_timestamp = standard_metadata.egress_global_timestamp;
        hdr.int_sinet2.qdepth = (bit<32>)standard_metadata.deq_qdepth;
    }

    table int_sinet_table {
        actions = {
            add_int1;
            add_int2;
            NoAction;
        }
        default_action = NoAction();
    }

    apply {
        if(hdr.sinet.isValid()) {
	    // modify the variable srcAddr length
	    if(hdr.sinet.srcAddr_length >= 152) {
	       hdr.sinet_extend_src_graft1.setValid();
	       if(hdr.sinet.dstAddr_length >= 32) {
		   hdr.sinet_extend_src_graft1.next_header = 0x90;
	       }
	       else {
		   hdr.sinet_extend_src_graft1.next_header = 0x88;
	       }
	       hdr.sinet_extend_src_graft1.srcAddr[119:16] = meta.sinetAddr_src[103:0];
	       hdr.sinet_extend_src_graft0.setValid();
	       hdr.sinet_extend_src_graft0.next_header = 0x80;
	       hdr.sinet_extend_src_graft0.srcAddr = meta.sinetAddr_src[223:104];
	       hdr.sinet.next_header = 0x80;
	       hdr.sinet.srcAddr = meta.sinetAddr_src[255:224];
	    }
	    else if(hdr.sinet.srcAddr_length >= 32) {
	       hdr.sinet_extend_src_graft0.setValid();
	       if(hdr.sinet.dstAddr_length >= 32) {
		   hdr.sinet_extend_src_graft0.next_header = 0x90;
	       }
	       else {
		   hdr.sinet_extend_src_graft0.next_header = 0x88;
	       }
	       hdr.sinet_extend_src_graft0.srcAddr = meta.sinetAddr_src[223:104];
	       hdr.sinet.next_header = 0x80;
	       hdr.sinet.srcAddr = meta.sinetAddr_src[255:224];
	    }
	    else {
	       hdr.sinet.next_header = 0x88;
	       hdr.sinet.srcAddr = meta.sinetAddr_src[255:224];
	    }

	    // modify the variable srcAddr length
	    if(hdr.sinet.dstAddr_length >= 152) {
	       hdr.sinet_extend_dst_graft1.setValid();
	       hdr.sinet_extend_dst_graft1.next_header = 0x88;
	       hdr.sinet_extend_dst_graft1.dstAddr[119:16] = meta.sinetAddr_dst[103:0];
	       hdr.sinet_extend_dst_graft0.setValid();
	       hdr.sinet_extend_dst_graft0.next_header = 0x90;
	       hdr.sinet_extend_dst_graft0.dstAddr = meta.sinetAddr_dst[223:104];
	       //hdr.sinet.next_header = 0x90;
	       hdr.sinet.dstAddr = meta.sinetAddr_dst[255:224];
	    }
	    else if(hdr.sinet.dstAddr_length >= 32) {
	       hdr.sinet_extend_dst_graft0.setValid();
	       hdr.sinet_extend_dst_graft0.next_header = 0x88;
	       hdr.sinet_extend_dst_graft0.dstAddr = meta.sinetAddr_dst[223:104];
	       //hdr.sinet.next_header = 0x90;
	       hdr.sinet.dstAddr = meta.sinetAddr_dst[255:224];
	    }
	    else {
	       hdr.sinet.dstAddr = meta.sinetAddr_dst[255:224];
	    }
        }
        if(hdr.int_sinet1.isValid() && hdr.int_sinet2.isValid()){
            int_sinet_table.apply();
        }
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
        packet.emit(hdr.sinet);
        packet.emit(hdr.sinet_extend_src_graft0);
        packet.emit(hdr.sinet_extend_src_graft1);
        packet.emit(hdr.sinet_extend_dst_graft0);
        packet.emit(hdr.sinet_extend_dst_graft1);
        packet.emit(hdr.int_sinet1);
        packet.emit(hdr.int_sinet2);
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
