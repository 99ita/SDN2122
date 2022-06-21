from turtle import update
from matplotlib.cbook import ls_mapper
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.ofproto import ether
import time
import threading

#Set to true to use the firewall
firewall = False

def apply_mask(ip):
    ip = ip.split('.')
    ip = ip[0] + '.' + ip[1] + '.' + ip[2]

    return ip

def router_to_router(dpid,port):
    if dpid == 17:
        if port == 1:
            dpid,port = 18,1
        elif port == 2:
            dpid,port = 19,2
    elif dpid == 18:
        if port == 1:
            dpid,port = 17,1
        elif port == 2:
            dpid,port = 19,1
    elif dpid == 19:
        if port == 1:
            dpid,port = 18,2
        elif port == 2:
            dpid,port = 17,1
    
    return dpid,port

class SwitchL3(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SwitchL3, self).__init__(*args, **kwargs)
        self.ip_to_mac = {}
        self.ip_to_port = {17: {'10.0.1' : 3, '10.0.2' : 1, '10.0.3' : 2},
                           18: {'10.0.1' : 1, '10.0.2' : 3, '10.0.3' : 2},
                           19: {'10.0.1' : 2, '10.0.2' : 1, '10.0.3' : 3}}
        self.router_ports_mac = {}
        self.router_ports_state = {}
        self.router_ports_to_ip = {17: {1 : '10.0.4.1', 2 : '10.0.6.2', 3 : '10.0.1.20'}, 
                                   18: {1 : '10.0.4.2', 2 : '10.0.5.1', 3 : '10.0.2.20'}, 
                                   19: {1 : '10.0.5.2', 2 : '10.0.6.1', 3 : '10.0.3.20'}}
        
        self.packet_queue = {}
        self.links = {}
        self.fst = True
        self.routersDP = []
        t = threading.Thread(target=self.port_status_thread)
        t.daemon = True
        t.start()

    def remove_table_flows(self, datapath):
        match, instructions = datapath.ofproto_parser.OFPMatch(),[]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        flow_mod = parser.OFPFlowMod(datapath, 0, 0, 0,
                                    ofproto.OFPFC_DELETE, 0, 0,
                                    1,
                                    ofproto.OFPCML_NO_BUFFER,
                                    ofproto.OFPP_ANY,
                                    ofproto.OFPG_ANY, 0,
                                    match, instructions)
        datapath.send_msg(flow_mod)
        self.logger.info(f"Deleted all flow mods in router {datapath.id}!\n")
        
        self.start_setup(datapath)
    

    def resolve_paths(self):
        link12 = False
        link23 = False
        link31 = False
        l1 = []
        for i in self.ip_to_port.values():
            for ii in i.values():
                l1.append(ii) 

        try:
            if self.router_ports_state[17][1] == 4 and self.router_ports_state[18][1] == 4:
                link12 = True
            if self.router_ports_state[18][2] == 4 and self.router_ports_state[19][1] == 4:
                link23 = True
            if self.router_ports_state[19][2] == 4 and self.router_ports_state[17][2] == 4:
                link31 = True
        except KeyError:
            return

        if not link12:
            self.ip_to_port[17]['10.0.2'] = 2
            self.ip_to_port[18]['10.0.1'] = 2
        else:
            self.ip_to_port[17]['10.0.2'] = 1
            self.ip_to_port[18]['10.0.1'] = 1

        if not link23:
            self.ip_to_port[18]['10.0.3'] = 1
            self.ip_to_port[19]['10.0.2'] = 2
        else:
            self.ip_to_port[18]['10.0.3'] = 2
            self.ip_to_port[19]['10.0.2'] = 1

        if not link31:
            self.ip_to_port[17]['10.0.3'] = 1
            self.ip_to_port[19]['10.0.1'] = 1
        else:
            self.ip_to_port[17]['10.0.3'] = 2
            self.ip_to_port[19]['10.0.1'] = 2


        l2 = []
        for i in self.ip_to_port.values():
            for ii in i.values():
                l2.append(ii) 

        updated = True
        if len(l1)== len(l2) and len(l1) == sum([1 for i, j in zip(l1, l2) if i == j]):
            updated = False

        if self.fst:
            print("Topology known!")
            self.fst = False
        if updated:
            print("Topology changed!\n")
            for dp in self.routersDP:
                self.remove_table_flows(dp)

            

    def port_status_thread(self):
        while True:
            for dp in self.routersDP:
                self.port_desc(dp)
            time.sleep(0.1)


    def start_setup(self,datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if firewall:
            #Block all traffic
            match = parser.OFPMatch()
            actions = []
            self.add_flow(datapath, 0, match, actions)

            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            #Allow ARP traffic
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
            self.add_flow(datapath, 100, match, actions)

            #Allow traffic to server from h6
            match = parser.OFPMatch(eth_type=0x0800,
                                    ip_proto=0x06,
                                    ipv4_dst='10.0.1.1',
                                    ipv4_src='10.0.2.3',
                                    tcp_dst=5555)
            self.add_flow(datapath, 10, match, actions)
            
            #Allow traffic to server from h9
            match = parser.OFPMatch(eth_type=0x0800,
                                    ip_proto=0x06,
                                    ipv4_dst='10.0.1.1',
                                    ipv4_src='10.0.3.3',
                                    tcp_dst=5555)
            self.add_flow(datapath, 10, match, actions)
            
            #Allow traffic to h6 from server
            match = parser.OFPMatch(eth_type=0x0800,
                                    ip_proto=0x06,
                                    ipv4_dst='10.0.2.3',
                                    ipv4_src='10.0.1.1',
                                    tcp_src=5555)
            self.add_flow(datapath, 10, match, actions)
            
            #Allow traffic to h9 from server
            match = parser.OFPMatch(eth_type=0x0800,
                                    ip_proto=0x06,
                                    ipv4_dst='10.0.3.3',
                                    ipv4_src='10.0.1.1',
                                    tcp_src=5555)
            self.add_flow(datapath, 10, match, actions)
        else:
            #Allow all traffic
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, 0, match, actions)

        #Block IPv6 traffic
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6)
        actions = []
        self.add_flow(datapath, 1, match, actions)

        if firewall:
            self.logger.info(f"Setting router {datapath.id} table to default (firewall)\n")
        else:
            self.logger.info(f"Setting router {datapath.id} table to default\n")



    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath

        self.start_setup(datapath)

        if datapath not in self.routersDP:
            self.routersDP.append(datapath)


    def port_desc(self, datapath):
        ofparser = datapath.ofproto_parser

        req = ofparser.OFPPortDescStatsRequest(datapath,0)
        datapath.send_msg(req)


    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handle(self,ev):

        dpid = ev.msg.datapath.id
        self.router_ports_mac.setdefault(dpid, {})
        self.router_ports_state.setdefault(dpid, {})
        
        for p in ev.msg.body:
            self.router_ports_mac[dpid].update({p.port_no: p.hw_addr})
            self.router_ports_state[dpid].update({p.port_no: p.state})

        self.resolve_paths()
        

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
 

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        parser = msg.datapath.ofproto_parser
        dpid = msg.datapath.id        
        port = msg.match['in_port']
        pkt = packet.Packet(msg.data)

        #self.logger.info("\npacket-in %s" % (pkt,))

        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            #ARP handling
            self.handle_arp(msg, port, pkt_ethernet, pkt_arp)
            return
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
            if pkt_ipv4.dst in self.router_ports_to_ip[dpid].values():
                pkt_icmp = pkt.get_protocol(icmp.icmp)
                if pkt_icmp:
                    self.handle_icmp(msg, port, pkt_ethernet, pkt_ipv4, pkt_icmp)
                    return
            else:
                #Routing handling
                if apply_mask(pkt_ipv4.dst) in self.ip_to_port[dpid].keys():
                    out_port = self.ip_to_port[dpid][apply_mask(pkt_ipv4.dst)]
                    self.logger.info("\nPacket received by router %s from %s to %s ", dpid, pkt_ipv4.src, pkt_ipv4.dst)
                    self.ip_to_mac.setdefault(dpid, {})
                    if out_port == 3:
                        if pkt_ipv4.dst in self.ip_to_mac[dpid].keys():
                            pkt_ethernet.src = self.router_ports_mac[dpid][out_port]
                            pkt_ethernet.dst = self.ip_to_mac[dpid][pkt_ipv4.dst]
                            self.send_packet(msg.datapath,out_port,pkt)

                            match = parser.OFPMatch(eth_type=0x0800,
                                                    ip_proto=pkt_ipv4.proto,
                                                    ipv4_dst=pkt_ipv4.dst,
                                                    ipv4_src=pkt_ipv4.src)
                            actions = [parser.OFPActionSetField(eth_dst=pkt_ethernet.dst),
                                       parser.OFPActionSetField(eth_src=pkt_ethernet.src),
                                       parser.OFPActionOutput(out_port)]
                            self.add_flow(msg.datapath,5000,match,actions)
                            self.logger.info('Added flow table entry!')
                            return

                        else:
                            #Send ARP Request
                            self.packet_queue.setdefault(dpid,{})
                            self.packet_queue[dpid].setdefault(pkt_ipv4.dst,[])
                            self.packet_queue[dpid][pkt_ipv4.dst].append(msg)
                            self.logger.info("\nRouter %s doesn't know MAC of %s adding packet to queue", dpid, pkt_ipv4.dst)
                            self.send_arp_request(msg, pkt_ipv4)
                            return
                    else:
                        pkt_ethernet.src = self.router_ports_mac[dpid][out_port]
                        d,p = router_to_router(dpid,out_port)
                        pkt_ethernet.dst = self.router_ports_mac[d][p]
                        self.send_packet(msg.datapath,out_port,pkt)

                        match = parser.OFPMatch(eth_type=0x0800,
                                                ip_proto=pkt_ipv4.proto,
                                                ipv4_dst=pkt_ipv4.dst,
                                                ipv4_src=pkt_ipv4.src)
                        actions = [parser.OFPActionSetField(eth_dst=pkt_ethernet.dst),
                                    parser.OFPActionSetField(eth_src=pkt_ethernet.src),
                                    parser.OFPActionOutput(out_port)]
                        self.add_flow(msg.datapath,5000,match,actions)
                        self.logger.info('Added flow table entry!')

                else:
                    self.logger.info("\nPacket received by router %s from %s to %s (unknown destination)", dpid, pkt_ipv4.src, pkt_ipv4.dst)
                    self.send_icmp_unreachable(msg, port, pkt_ethernet, pkt_ipv4)
                    #Send ICMP network unreachable
                   


    def send_arp_request(self, msg, pkt_ipv4):
        dpid = msg.datapath.id
        out_port = self.ip_to_port[dpid][apply_mask(pkt_ipv4.dst)]
        src_mac = self.router_ports_mac[dpid][out_port]
        src_ip = self.router_ports_to_ip[dpid][out_port]


        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_ARP,
                                           dst='ff:ff:ff:ff:ff:ff',
                                           src=src_mac))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REQUEST,
                                 src_mac=src_mac,
                                 src_ip=src_ip,
                                 dst_mac='ff:ff:ff:ff:ff:ff',
                                 dst_ip=pkt_ipv4.dst))

        self.send_packet(msg.datapath,out_port,pkt)

        self.logger.info("\nRouter %s sending ARP Request from port %s to learn MAC of %s", dpid, out_port, pkt_ipv4.dst)


    def send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
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

        if pkt_arp.dst_ip in self.router_ports_to_ip[dpid].values() and pkt_arp.opcode == arp.ARP_REQUEST:

            self.logger.info("\nARP Request received by router %s from %s in port %s ", dpid, pkt_arp.src_ip, port)

            port_mac = self.router_ports_mac[dpid][port]

            pkt = packet.Packet()
            pkt.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_ARP,
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

        elif pkt_arp.dst_ip in self.router_ports_to_ip[dpid].values() and pkt_arp.opcode == arp.ARP_REPLY:
            self.logger.info("\nARP Reply received by router %s from %s with MAC %s", dpid, pkt_arp.src_ip, pkt_arp.src_mac)
            self.ip_to_mac.setdefault(dpid, {})
            self.ip_to_mac[dpid][pkt_arp.src_ip] = pkt_arp.src_mac

            for m in self.packet_queue[dpid][pkt_arp.src_ip]:
                dpid = m.datapath.id        
                pkt = packet.Packet(m.data)
                pkt_eth = pkt.get_protocol(ethernet.ethernet)
                pkt_v4 = pkt.get_protocol(ipv4.ipv4)
                out_port = self.ip_to_port[dpid][apply_mask(pkt_arp.src_ip)]
                pkt_eth.src = self.router_ports_mac[dpid][out_port]
                pkt_eth.dst = self.ip_to_mac[dpid][pkt_arp.src_ip]
                self.send_packet(msg.datapath,out_port,pkt)
                self.logger.info("Router %s sent queued packet from %s to %s", dpid, pkt_v4.src, pkt_v4.dst)


            #cycle through all packets to this ip and forward them
            return
        else:
            self.logger.info("\nARP Packet dropped router %s, %s not an interface ip", dpid, pkt_arp.dst_ip)
            
            #Any other case pass
            return


    def handle_icmp(self, msg, port, pkt_ethernet, pkt_ipv4, pkt_icmp):
        # Send ICMP echo reply.
        parser = msg.datapath.ofproto_parser

        dpid = msg.datapath.id
        src_ip = pkt_ipv4.src
        self.logger.info('\nICMP echo request received by router %s port %s from %s to %s.', dpid, port, src_ip, pkt_ipv4.dst)
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst=pkt_ethernet.src,
                                           src=self.router_ports_mac[dpid][port]))
        pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,
                                   src=self.router_ports_to_ip[dpid][port],
                                   proto=pkt_ipv4.proto))
        pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
                                   code=icmp.ICMP_ECHO_REPLY_CODE,
                                   csum=0,
                                   data=pkt_icmp.data))
        self.send_packet(msg.datapath, port, pkt)
        self.logger.info('Send ICMP echo reply to [%s].', src_ip)


        match = parser.OFPMatch(eth_type=0x0800,
                                ip_proto=pkt_ipv4.proto,
                                ipv4_dst=pkt_ipv4.dst,
                                ipv4_src=pkt_ipv4.src,
                                icmpv4_type=0x08)

        actions = [parser.OFPActionSetField(ipv4_dst=pkt_ipv4.src),
                   parser.OFPActionSetField(ipv4_src=pkt_ipv4.dst),
                   parser.OFPActionSetField(eth_dst=pkt_ethernet.src),
                   parser.OFPActionSetField(eth_src=pkt_ethernet.dst),
                   parser.OFPActionSetField(icmpv4_type=0x00),
                   parser.OFPActionSetField(icmpv4_code=0x00),
                   parser.OFPActionOutput(msg.datapath.ofproto.OFPP_IN_PORT)]

        self.add_flow(msg.datapath,5000,match,actions)

        self.logger.info('Added flow table entry!')


    def send_icmp_unreachable(self, msg, port, pkt_ethernet, pkt_ipv4):
        port_mac = self.router_ports_mac[msg.datapath.id][port]

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
                                    src=self.router_ports_to_ip[msg.datapath.id][port],
                                    proto=pkt_ipv4.proto))
        pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_DEST_UNREACH,
                                    code=icmp.ICMP_HOST_UNREACH_CODE,
                                    csum=0,
                                    data=icmp_data))
        self.send_packet(msg.datapath, port, pkt)

        self.logger.info("Router %s sending ICMP Destination Unreachable to %s", msg.datapath.id, pkt_ipv4.src)

