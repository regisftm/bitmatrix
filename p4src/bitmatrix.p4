/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "includes/headers.p4"
#include "includes/parser.p4"

#define BITMATRIX_SIZE          2048

field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.id;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    update ipv4_checksum if (ipv4.ihl == 5);
}

action _drop() {
    drop();
}

header_type routing_metadata_t {
    fields {
        nhop_ipv4   : 32;
        nhop_add    : 48;
    }
}

metadata routing_metadata_t routing_metadata;

////////////////////////////////////////////////////////////////////////
// bitmatrix definitions

header_type custom_metadata_t {
    fields {
        bitmatrix_idx    : 16;
        bitmatrix_flag   :  4;
        bitmatrix_ptr    :  1;
        bitmatrix_tenant :  4;
        bitmatrix_value  : 20;
    }
}

metadata custom_metadata_t custom_metadata;

field_list hash_fields {
    ipv4.version;       // 4
    ipv4.ihl;           // 4
    ipv4.totalLen;      //16
    ipv4.id;            //16
    ipv4.flags;         // 3
    ipv4.fragOffset;    //13
    ipv4.protocol;      // 8
    ipv4.srcAddr;       //32
    ipv4.dstAddr;       //32
    payld.userdata8B;   //64
}

field_list_calculation hash {
    input { 
        hash_fields;
    }
    algorithm : crc16;
    output_width : 16;
}


register bitmatrix_0{
    width : 4;
    instance_count : BITMATRIX_SIZE;
}


register counter_array_0A{
    width : 20;
    instance_count : BITMATRIX_SIZE;
}

register counter_array_0B{
    width : 20;
    instance_count : BITMATRIX_SIZE;
}

register counter_array_0C{
    width : 20;
    instance_count : BITMATRIX_SIZE;
}

register counter_array_0D{
    width : 20;
    instance_count : BITMATRIX_SIZE;
}




register bitmatrix_1{
    width : 4;
    instance_count : BITMATRIX_SIZE;
}


register counter_array_1A{
    width : 20;
    instance_count : BITMATRIX_SIZE;
}

register counter_array_1B{
    width : 20;
    instance_count : BITMATRIX_SIZE;
}

register counter_array_1C{
    width : 20;
    instance_count : BITMATRIX_SIZE;
}

register counter_array_1D{
    width : 20;
    instance_count : BITMATRIX_SIZE;
}




register bitmatrix_pointer{
    width : 1;
    instance_count : 1;
}

////////////////////////////////////////////////////////////////////////
// counters

counter pckt_counter {
    type: packets_and_bytes;
    static: count_table;
    instance_count: 1;
}

action count_action() {
    count(pckt_counter, 0);
    register_read(custom_metadata.bitmatrix_ptr, bitmatrix_pointer, 0);   
}

table count_table {
    actions {
        count_action;
    }
    size : 1;
}


counter pckt_counter_0 {
    type: packets_and_bytes;
    direct : set_bitmatrix_0_table;
}

counter pckt_counter_1 {
    type: packets_and_bytes;
    direct : set_bitmatrix_1_table;
}




////////////////////////////////////////////////////////////////////////
// bitmatrix_0

action set_bitmatrix_0(tenant_flag) {
    modify_field_with_hash_based_offset(custom_metadata.bitmatrix_idx, 0, hash, BITMATRIX_SIZE - 1);
    register_read(custom_metadata.bitmatrix_flag, bitmatrix_0, custom_metadata.bitmatrix_idx);
    bit_or(custom_metadata.bitmatrix_flag, custom_metadata.bitmatrix_flag, tenant_flag);
    register_write(bitmatrix_0, custom_metadata.bitmatrix_idx, custom_metadata.bitmatrix_flag);
    modify_field(custom_metadata.bitmatrix_tenant, tenant_flag);

}

table set_bitmatrix_0_table {
    reads {
        ipv4.srcAddr : lpm;
    }
    actions {
        set_bitmatrix_0;
        _drop;
    }
    size: 32;
}

////////////////////////////////////////////////////////////////////////
// bitmatrix_1

action set_bitmatrix_1(tenant_flag) {
    modify_field_with_hash_based_offset(custom_metadata.bitmatrix_idx, 0, hash, BITMATRIX_SIZE - 1);
    register_read(custom_metadata.bitmatrix_flag, bitmatrix_1, custom_metadata.bitmatrix_idx);
    bit_or(custom_metadata.bitmatrix_flag, custom_metadata.bitmatrix_flag, tenant_flag);
    register_write(bitmatrix_1, custom_metadata.bitmatrix_idx, custom_metadata.bitmatrix_flag);
    modify_field(custom_metadata.bitmatrix_tenant, tenant_flag);
}

table set_bitmatrix_1_table {
    reads {
        ipv4.srcAddr : lpm;
    }
    actions {
        set_bitmatrix_1;
        _drop;
    }
    size: 32;
}

////////////////////////////////////////////////////////////////////////
// counter arrays 0

action set_counter_array_0A() {
    register_read(custom_metadata.bitmatrix_value, counter_array_0A, custom_metadata.bitmatrix_idx);
    add_to_field(custom_metadata.bitmatrix_value, ipv4.totalLen + 20);
    register_write(counter_array_0A, custom_metadata.bitmatrix_idx, custom_metadata.bitmatrix_value);
}

table set_counter_array_0A_table {
    actions {
        set_counter_array_0A;
    }
    size : 1;
}

action set_counter_array_0B() {
    register_read(custom_metadata.bitmatrix_value, counter_array_0B, custom_metadata.bitmatrix_idx);
    add_to_field(custom_metadata.bitmatrix_value, ipv4.totalLen + 20);
    register_write(counter_array_0B, custom_metadata.bitmatrix_idx, custom_metadata.bitmatrix_value);
}

table set_counter_array_0B_table {
    actions {
        set_counter_array_0B;
    }
    size : 1;
}

action set_counter_array_0C() {
    register_read(custom_metadata.bitmatrix_value, counter_array_0C, custom_metadata.bitmatrix_idx);
    add_to_field(custom_metadata.bitmatrix_value, ipv4.totalLen + 20);
    register_write(counter_array_0C, custom_metadata.bitmatrix_idx, custom_metadata.bitmatrix_value);
}

table set_counter_array_0C_table {
    actions {
        set_counter_array_0C;
    }
    size : 1;
}

action set_counter_array_0D() {
    register_read(custom_metadata.bitmatrix_value, counter_array_0D, custom_metadata.bitmatrix_idx);
    add_to_field(custom_metadata.bitmatrix_value, ipv4.totalLen + 20);
    register_write(counter_array_0D, custom_metadata.bitmatrix_idx, custom_metadata.bitmatrix_value);
}

table set_counter_array_0D_table {
    actions {
        set_counter_array_0D;
    }
    size : 1;
}


////////////////////////////////////////////////////////////////////////
// counter arrays 1

action set_counter_array_1A() {
    register_read(custom_metadata.bitmatrix_value, counter_array_1A, custom_metadata.bitmatrix_idx);
    add_to_field(custom_metadata.bitmatrix_value, ipv4.totalLen + 20);
    register_write(counter_array_1A, custom_metadata.bitmatrix_idx, custom_metadata.bitmatrix_value);
}

table set_counter_array_1A_table {
    actions {
        set_counter_array_1A;
    }
    size : 1;
}

action set_counter_array_1B() {
    register_read(custom_metadata.bitmatrix_value, counter_array_1B, custom_metadata.bitmatrix_idx);
    add_to_field(custom_metadata.bitmatrix_value, ipv4.totalLen + 20);
    register_write(counter_array_1B, custom_metadata.bitmatrix_idx, custom_metadata.bitmatrix_value);
}

table set_counter_array_1B_table {
    actions {
        set_counter_array_1B;
    }
    size : 1;
}

action set_counter_array_1C() {
    register_read(custom_metadata.bitmatrix_value, counter_array_1C, custom_metadata.bitmatrix_idx);
    add_to_field(custom_metadata.bitmatrix_value, ipv4.totalLen + 20);
    register_write(counter_array_1C, custom_metadata.bitmatrix_idx, custom_metadata.bitmatrix_value);
}

table set_counter_array_1C_table {
    actions {
        set_counter_array_1C;
    }
    size : 1;
}

action set_counter_array_1D() {
    register_read(custom_metadata.bitmatrix_value, counter_array_1D, custom_metadata.bitmatrix_idx);
    add_to_field(custom_metadata.bitmatrix_value, ipv4.totalLen + 20);
    register_write(counter_array_1D, custom_metadata.bitmatrix_idx, custom_metadata.bitmatrix_value);
}

table set_counter_array_1D_table {
    actions {
        set_counter_array_1D;
    }
    size : 1;
}


////////////////////////////////////////////////////////////////////////
// forwarding

action set_nhop(nhop_ipv4, port) {
    modify_field(routing_metadata.nhop_ipv4, nhop_ipv4);
    modify_field(standard_metadata.egress_spec, port);
    modify_field(ipv4.ttl, ipv4.ttl - 1);
}

table ipv4_lpm {
    reads {
        ipv4.dstAddr : lpm;
    }
    actions {
        set_nhop;
        _drop;
    }
    size: 1024;
}

////////////////////////////////////////////////////////////////////////

action set_dmac(dmac) {
    modify_field(eth.dstAddr, dmac);
}

table forward {
    reads {
        routing_metadata.nhop_ipv4 : exact;
    }
    actions {
        set_dmac;
        _drop;
    }
    size: 512;
}

////////////////////////////////////////////////////////////////////////

action rewrite_mac(smac) {
    modify_field(eth.srcAddr, smac);
}

table send_frame {
    reads {
        standard_metadata.egress_port: exact;
    }
    actions {
        rewrite_mac;
        _drop;
    }
    size: 256;
}

////////////////////////////////////////////////////////////////////////

control ingress {
    if(valid(ipv4) and ipv4.ttl > 0) {
        apply(count_table);
        if (custom_metadata.bitmatrix_ptr == 0) {
            apply(set_bitmatrix_0_table); 
            if (custom_metadata.bitmatrix_tenant == 1) {
                apply(set_counter_array_0A_table);
            }            
            else { 
                if (custom_metadata.bitmatrix_tenant == 2) {
                apply(set_counter_array_0B_table);
                }
                else {
                    if (custom_metadata.bitmatrix_tenant == 4) {
                    apply(set_counter_array_0C_table);
                    }
                    else {
                    apply(set_counter_array_0D_table);
                    }
                }
            }
        }
        if (custom_metadata.bitmatrix_ptr == 1) {
            apply(set_bitmatrix_1_table);
            if (custom_metadata.bitmatrix_tenant == 1) {
                apply(set_counter_array_1A_table);
            }            
            else { 
                if (custom_metadata.bitmatrix_tenant == 2) {
                apply(set_counter_array_1B_table);
                }
                else {
                    if (custom_metadata.bitmatrix_tenant == 4) {
                    apply(set_counter_array_1C_table);
                    }
                    else {
                    apply(set_counter_array_1D_table);
                    }
                }
            }
        }
        apply(ipv4_lpm);
        apply(forward);
    }
}

control egress {
    apply(send_frame);
}



