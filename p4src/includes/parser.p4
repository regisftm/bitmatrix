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

parser start {
    return parse_eth;
}

#define ETHERTYPE_IPV4          0x0800
#define IP_PROTOCOLS_ICMP       1
#define IP_PROTOCOLS_TCP        6
#define IP_PROTOCOLS_UDP        17

header eth_t eth;

parser parse_eth {
    extract(eth);
    return select(latest.etherType) {
        ETHERTYPE_IPV4      : parse_ipv4;        
        default: ingress;
    }
}

header ipv4_t ipv4;

parser parse_ipv4 {
    extract(ipv4);
    return select(latest.protocol) {
        IP_PROTOCOLS_ICMP   : parse_icmp;
        IP_PROTOCOLS_TCP    : parse_tcp;
        IP_PROTOCOLS_UDP    : parse_udp;
        default: ingress;
    }
}

header icmp_t icmp;

parser parse_icmp {
    extract(icmp);
    return parse_payld;
}


header tcp_t tcp;

parser parse_tcp {
    extract(tcp);
    return parse_payld;
}


header udp_t udp;

parser parse_udp {
    extract(udp);
    return parse_payld;
}


header payld_t payld;

parser parse_payld {
    extract(payld);
    return ingress;
}