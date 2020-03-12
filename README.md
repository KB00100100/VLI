# VLI

Various source codes of the VLI mechanism, including extension-header-size, rtt, throughput, delay and queue.


/**************Implementation of VLI (extension) headers Using only 26 lines of codes ********************/
//VLI header.
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

//VLI extension header --- srcAddr graft 0x80
header sinet_extend_src_graft_t {
    bit<8> next_header;
    bit<120> srcAddr;
}

//VLI extension header --- dstAddr graft 0x90
header sinet_extend_dst_graft_t {
    bit<8> next_header;
    bit<120> dstAddr;
}
/**************Implementation of VLI (extension) headers Using only 26 lines of codes ********************/
