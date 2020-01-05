# BitMatrix

> P4_14 BitMatrix implementation

This code demonstrates how to implement the BitMatrix using available commands and structures in the P4 language. To do that, the BitMatrix was implemented as a P4 register wide enough to host several bitmaps, each one used to measure traffic from a different tenant, identified by its Source IP subnetwork. The BitMatrix is used to aggregate bitmaps in order to register packets from different tenants. Tenant is defined as an external network, connected to the P4 network device. The goal is to use BitMatrix associated with counter arrays to estimate the amount of packets and bytes transmitted for each tenant and, in addiction, understand the path taken by those packets inside the network. Each packet received by the P4 device computes a hash value. This value is used to determine which position will be set in the BitMatrix, according to its origin (tenant). In this way, it is possible to determine which tenant is responsible for each packet in the network. 

In this proof of concept, a BitMatrix composed by three bitmaps was used. This resulted in a P4 register with a width equal to 3. Thus, it is possible to segment traffic from up to three tenants, setting different bitmaps in the BitMatrix according to which tenant originated the packet. Using a P4 table, a value for each tenant was assigned, according to its source IP network: 1 to tenant A, 2 to tenant B and 4 to tenant C. Once the hash value of each packet is computed, a modulo operation is applied to the value to determine what position should be set in the BitMatrix. This is achieved by using the P4 primitive action modify\_field\_with\_hash\_based\_offset. As each position of the BitMatrix has three bits, we used another P4 primitive action named bit\_or to set the correct bit in that position of BitMatrix by performing a logical OR operation using the current value for the selected position and the tenant value. 


As an example, consider that the current value for a selected position is 4 (100 in binary). This indicates that a packet originated from tenant C has already set that position. Nevertheless, this has no impact for the same position in other bitmaps in the BitMatrix. If a packet from tenant A falls in the same position, the logical OR operation is applied using the current value in the BitMatrix (4 or 100 in binary) and the tenant A value (1 or 001 in binary), resulting in the new value 5 (101 in binary). 

A P4 register was also used to create counter arrays. The usage of counter array targets to count the number of bytes transmitted for each packet. For this, the register used to create the counter array has the same length of BitMatrix, but a width large enough to avoid overflow. We used a width of 20 bits, which allows to store up to 1 Mbyte. Considering that each packet has a size of 1,500 bytes, it is enough to sum bytes from up to 699 packets, for each position. So, this can still counting bytes from packets until it reaches 700 hash collisions for that one specific position. Different from BitMatrix, the counter arrays can not be combined into an unique register. Thus, one counter array was defined for each tenant.

To continue the BitMatrix evaluation we used the results from Figure \ref{fig:coliocu} and the percentage of hash collision was target to keep under 10\%. The hash collision was calculated by dividing the total number of positions marked in the bit array by the number of processed packets. This approach resulted in an epoch of 60s, a bandwidth limited to 1Mbps and bitmap size of 16384 positions. The setup for this experiment was constructed using Mininet network emulator customized in order to enable P4 switch in the emulated network.

The topology used was composed of three hosts and four P4 switches. Each host received an IP address from a different network, emulating different tenants. The topology is presented in Figure \ref{topology}.



The paths between tenants were arbitrarily defined as shown in Table below.

| Tenant Pairs | Switches hop by hop in order|
|:------------:|:--------------------------- |
| A to B       | sw1 - sw3                   |
| B to A       | sw3 - sw1                   |
| A to C       | sw1 - sw2 - sw4             |
| C to A       | sw4 - sw2 - sw1             |
| B to C       | sw3 - sw4                   |
| C to B       | sw4 - sw3                   |

Every packet processed by the P4 switches generates entries in its corresponding BitMatrix (instantiated in each switch). Our P4 implementation consists of processing packets for the BitMatrix and can be described in the following general steps:

- Completely parse the packet headers of Layer 2, 3, 4 and the first 8 Bytes of the payload;
- Select the packet headers to be used in the hashing algorithm;
- Determine the position in the bitmap;
- Determine the position (using the same hashing value) in the counter array to sum the total bytes of the current packet with the previous ones;
- Forward the packet to the next hop.
