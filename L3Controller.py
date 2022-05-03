from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ether_types
from ryu.lib.packet import packet_base
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import packet_base
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.ofproto import ether

ETHERNET = ethernet.ethernet.__name__
IPV4 = ipv4.ipv4.__name__
ARP = arp.arp.__name__
ICMP = icmp.icmp.__name__
TCP = tcp.tcp.__name__
UDP = udp.udp.__name__






class SwitchL3(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SwitchL3, self).__init__(*args, **kwargs)
        self.ip_to_mac = {}
        self.ip_to_port = {'10.0.1.1' : 1, '10.0.1.2' : 1, '10.0.1.3' : 1,
                           '10.0.2.1' : 2, '10.0.2.2' : 2, '10.0.2.3' : 2,
                           '10.0.3.1' : 3, '10.0.3.2' : 3, '10.0.3.3' : 3,}
        self.router_ports = {}
        self.router_ports_to_ip = {1 : '10.0.1.20', 2 : '10.0.2.20', 3 : '10.0.3.20'}
        
        self.packet_queue = {}


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, 0, match, actions)

        match = parser.OFPMatch(eth_type = ether_types.ETH_TYPE_IPV6)
        actions = []

        self.add_flow(datapath, 1, match, actions)
        self.port_desc(datapath)


    def port_desc(self, datapath):
        ofparser = datapath.ofproto_parser

        req = ofparser.OFPPortDescStatsRequest(datapath,0)
        datapath.send_msg(req)


    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handle(self,ev):

        dpid = ev.msg.datapath.id
        self.router_ports.setdefault(dpid, {})
        for p in ev.msg.body:
            self.router_ports[dpid].update({ p.port_no: p.hw_addr})
        print(self.router_ports)


    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
 
   
    '''def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        header_list = dict((p.protocol_name, p)
                           for p in pkt.protocols
                           if isinstance(p, packet_base.PacketBase))


        dpid = datapath.id

        

        # Analyze event type.
        if ARP in header_list:
            self.packetin_arp(msg, header_list)
            return

        if IPV4 in header_list:
            rt_ports = self.address_data.get_default_gw()
            if header_list[IPV4].dst in rt_ports:
                # Packet to router's port.
                if ICMP in header_list:
                    if header_list[ICMP].type == icmp.ICMP_ECHO_REQUEST:
                        self._packetin_icmp_req(msg, header_list)
                        return
                elif TCP in header_list or UDP in header_list:
                    self._packetin_tcp_udp(msg, header_list)
                    return
            else:
                # Packet to internal host or gateway router.
                self._packetin_to_node(msg, header_list)
                return





        eth = header_list[ETHERNET]
        ipv4 = header_list[IPV4]

        src_mac = eth.src
        src_ip = ipv4.src
        dst_ip = ipv4.dst

        self.ip_to_mac.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address 
        self.ip_to_mac[dpid][src_ip] = src_mac

        if dst_ip in self.ip_to_mac[dpid]:
            out_port = self.mac_to_port[dpid][dst_ip]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)'''


    

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = msg.datapath.id
        pkt = packet.Packet(msg.data)
        port = msg.match['in_port']
        self.logger.info("packet-in %s" % (pkt,))

        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            #ARP handling
            self.handle_arp(msg, datapath, port, pkt_ethernet, pkt_arp)
            return
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
            if pkt_ipv4.dst in self.router_ports_to_ip.values():
                pkt_icmp = pkt.get_protocol(icmp.icmp)
                if pkt_icmp:
                    #ICMP handling
                    self.handle_icmp(datapath, port, pkt_ethernet, pkt_ipv4, pkt_icmp)
                    return
            else:
                #Static routing handling
                if pkt_ipv4.dst in self.ip_to_port.keys():
                    self.logger.info("Packet received by router %s from %s to %s ", dpid, pkt_ipv4.src, pkt_ipv4.dst)
                    if pkt_ipv4.dst in self.ip_to_mac.keys():
                        out_port = self.ip_to_port[pkt_ipv4.dst]
                        pkt_ethernet.src = self.router_ports[dpid][out_port]
                        pkt_ethernet.dst = self.ip_to_mac[dpid][pkt_ipv4.dst]
                        
                        
                        return

                    else:
                        #Send ARP Request
                        self.packet_queue.setdefault(pkt_ipv4.dst,[])
                        self.packet_queue[pkt_ipv4.dst].append(msg)
                        self.logger.info("Router %s doesn't know MAC of %s adding packet to queue", dpid, pkt_ipv4.dst)
                        self.send_arp_request(msg, pkt_ethernet, pkt_ipv4)
                        return

                else:
                    self.logger.info("Packet received by router %s from %s to %s (unknown destination)", dpid, pkt_ipv4.src, pkt_ipv4.dst)
                    self.send_icmp_unreachable(msg, port, pkt_ethernet, pkt_ipv4)
                    #Send ICMP network unreachable
                   


    def send_arp_request(self, msg, pkt_ethernet, pkt_ipv4):
        out_port = self.ip_to_port[pkt_ipv4.dst]
        src_mac = self.router_ports[msg.datapath.id][out_port]
        src_ip = self.router_ports_to_ip[out_port]


        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst='ff:ff:ff:ff:ff:ff',
                                           src=src_mac))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REQUEST,
                                 src_mac=src_mac,
                                 src_ip=src_ip,
                                 dst_mac='ff:ff:ff:ff:ff:ff',
                                 dst_ip=pkt_ipv4.dst))

        self.send_packet(msg.datapath,out_port,pkt)

        self.logger.info("Router %s sending ARP Request from port %s to learn MAC of %s", msg.datapath.id, out_port, pkt_ipv4.dst)




    def send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)


    def handle_arp(self, msg, port, pkt_ethernet, pkt_arp):
        #ARP packet handling.
        dpid = msg.datapath.id

        if pkt_arp.dst_ip in self.router_ports_to_ip.values() and pkt_arp.opcode == arp.ARP_REQUEST:

            self.logger.info("ARP Request received by router %s from %s in port %s ", dpid, pkt_arp.src_ip, port)

            port_mac = self.router_ports[dpid][port]

            pkt = packet.Packet()
            pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst=pkt_ethernet.src,
                                           src=port_mac))
            pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                 src_mac=port_mac,
                                 src_ip=pkt_arp.dst_ip,
                                 dst_mac=pkt_arp.src_mac,
                                 dst_ip=pkt_arp.src_ip))
            self.send_packet(msg.datapath, port, pkt)

            self.logger.info("ARP Reply sent by router %s from port %s with MAC %s to %s", dpid, port, port_mac, pkt_arp.src_ip)

            return
        elif pkt_arp.dst_ip in self.router_ports_to_ip.values() and pkt_arp.opcode == arp.ARP_REPLY:
            self.logger.info("ARP Reply received by router %s from %s with MAC %s", port, pkt_arp.src_ip, pkt_arp.src_mac)
            self.ip_to_mac.setdefault(dpid, {})
            self.ip_to_mac[dpid][pkt_arp.src_ip] = pkt_arp.src_mac

            #wake arp reply waiting thread
            return
        else:
            #Any other case pass
            return


    def hanlde_icmp(self, msg, port, pkt_ethernet, pkt_ipv4, pkt_icmp):
        # Send ICMP echo reply.

        dpid = msg.datapath.id
        src_ip = pkt_ipv4.src
        self.logger.info('ICMP echo request received by router %s from %s to router port %s.', dpid, src_ip, port)
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst=pkt_ethernet.src,
                                           src=self.router_ports[dpid][port]))
        pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,
                                   src=self.router_ports_to_ip[port],
                                   proto=pkt_ipv4.proto))
        pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
                                   code=icmp.ICMP_ECHO_REPLY_CODE,
                                   csum=0,
                                   data=pkt_icmp.data))
        self.send_packet(msg.datapath, port, pkt)
        self.logger.info('Send ICMP echo reply to [%s].', src_ip)


    def send_icmp_unreachable(self, msg, port, pkt_ethernet, pkt_ipv4):
        port_mac = self.router_ports[msg.datapath.id][port]

        offset = ethernet.ethernet._MIN_LEN
        end_of_data = offset + len(pkt_ipv4) + 128
        ip_datagram = bytearray()
        ip_datagram += msg.data[offset:end_of_data]
        data_len = int(len(ip_datagram) / 4)
        length_modulus = int(len(ip_datagram) % 4)
        if length_modulus:
            data_len += 1
            ip_datagram += bytearray([0] * (4 - length_modulus))

        icmp_data = icmp.dest_unreach(data_len=data_len, data=ip_datagram)

        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                            dst=pkt_ethernet.src,
                                            src=port_mac))
        pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,
                                    src=self.router_ports_to_ip[port],
                                    proto=pkt_ipv4.proto))
        pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_DEST_UNREACH,
                                    code=icmp.ICMP_HOST_UNREACH_CODE,
                                    csum=0,
                                    data=icmp_data))
        self.send_packet(msg.datapath, port, pkt)

        self.logger.info("Router %s sending ICMP Destination Unreachable to %s", msg.datapath.id, pkt_ipv4.src)



    def _packetin_tcp_udp(self, msg, header_list):
        # Send ICMP port unreach error.
        in_port = self.ofctl.get_packetin_inport(msg)
        self.ofctl.send_icmp(in_port, header_list, self.vlan_id,
                             icmp.ICMP_DEST_UNREACH,
                             icmp.ICMP_PORT_UNREACH_CODE,
                             msg_data=msg.data)

        srcip = ip_addr_ntoa(header_list[IPV4].src)
        dstip = ip_addr_ntoa(header_list[IPV4].dst)
        self.logger.info('Receive TCP/UDP from [%s] to router port [%s].',
                         srcip, dstip, extra=self.sw_id)
        self.logger.info('Send ICMP destination unreachable to [%s].', srcip,
                         extra=self.sw_id)

    def _packetin_to_node(self, msg, header_list):
        if len(self.packet_buffer) >= MAX_SUSPENDPACKETS:
            self.logger.info('Packet is dropped, MAX_SUSPENDPACKETS exceeded.',
                             extra=self.sw_id)
            return

        # Send ARP request to get node MAC address.
        in_port = msg.match['in_port']
        src_ip = None
        dst_ip = header_list[IPV4].dst
        srcip = header_list[IPV4].src
        dstip = ip_addr_ntoa(dst_ip)

        address = self.address_data.get_data(ip=dst_ip)
        if address is not None:
            log_msg = 'Receive IP packet from [%s] to an internal host [%s].'
            self.logger.info(log_msg, srcip, dstip, extra=self.sw_id)
            src_ip = address.default_gw
        else:
            route = self.routing_tbl.get_data(dst_ip=dst_ip)
            if route is not None:
                log_msg = 'Receive IP packet from [%s] to [%s].'
                self.logger.info(log_msg, srcip, dstip, extra=self.sw_id)
                gw_address = self.address_data.get_data(ip=route.gateway_ip)
                if gw_address is not None:
                    src_ip = gw_address.default_gw
                    dst_ip = route.gateway_ip

        if src_ip is not None:
            self.packet_buffer.add(in_port, header_list, msg.data)
            self.send_arp_request(src_ip, dst_ip, in_port=in_port)
            self.logger.info('Send ARP request (flood)', extra=self.sw_id)

    def _packetin_invalid_ttl(self, msg, header_list):
        # Send ICMP TTL error.
        srcip = ip_addr_ntoa(header_list[IPV4].src)
        self.logger.info('Receive invalid ttl packet from [%s].', srcip,
                         extra=self.sw_id)

        in_port = self.ofctl.get_packetin_inport(msg)
        src_ip = self._get_send_port_ip(header_list)
        if src_ip is not None:
            self.ofctl.send_icmp(in_port, header_list, self.vlan_id,
                                 icmp.ICMP_TIME_EXCEEDED,
                                 icmp.ICMP_TTL_EXPIRED_CODE,
                                 msg_data=msg.data, src_ip=src_ip)
            self.logger.info('Send ICMP time exceeded to [%s].', srcip,
                             extra=self.sw_id)

    def send_arp_all_gw(self):
        gateways = self.routing_tbl.get_gateways()
        for gateway in gateways:
            address = self.address_data.get_data(ip=gateway)
            self.send_arp_request(address.default_gw, gateway)

    def send_arp_request(self, src_ip, dst_ip, in_port=None):
        # Send ARP request from all ports.
        for send_port in self.port_data.values():
            if in_port is None or in_port != send_port.port_no:
                src_mac = send_port.mac
                dst_mac = mac_lib.BROADCAST_STR
                arp_target_mac = mac_lib.DONTCARE_STR
                inport = self.ofctl.dp.ofproto.OFPP_CONTROLLER
                output = send_port.port_no
                self.ofctl.send_arp(arp.ARP_REQUEST, self.vlan_id,
                                    src_mac, dst_mac, src_ip, dst_ip,
                                    arp_target_mac, inport, output)