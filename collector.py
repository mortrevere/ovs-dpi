#! /usr/bin/python3

from contextlib import contextmanager
import signal

def raise_error(signum, frame):
    """This handler will raise an error inside gethostbyname"""
    raise OSError

@contextmanager
def set_signal(signum, handler):
    """Temporarily set signal"""
    old_handler = signal.getsignal(signum)
    signal.signal(signum, handler)
    try:
        yield
    finally:
        signal.signal(signum, old_handler)

@contextmanager
def set_alarm(time):
    """Temporarily set alarm"""
    signal.setitimer(signal.ITIMER_REAL, time)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0) # Disable alarm

@contextmanager
def raise_on_timeout(time):
    """This context manager will raise an OSError unless
    The with scope is exited in time."""
    with set_signal(signal.SIGALRM, raise_error):
        with set_alarm(time):
            yield


import redis
r = redis.Redis(host='10.206.19.154', port=6379, db=0)
print(r.set('foo', 'bar'))
print(r.get('foo'))

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.topology import api

from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether, ofproto_v1_5
from ryu.lib.packet import ethernet, arp, packet, tcp, udp, ipv4, in_proto, ether_types, packet
from ryu.utils import binary_str

import socket
#from pktAnalyticsEngine import pktAnalyticsEngine
import hashlib

MISS_SEND_LENGTH = 200
BLOCK_IDLE_TIMEOUT = 30

class FirewallSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def delete_flow(self, dp, table_id, match):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        instructions = []
        flow_mod = parser.OFPFlowMod(dp, 0, 0, table_id, ofp.OFPFC_DELETE, 0, 0, 1, ofp.OFPCML_NO_BUFFER, ofp.OFPP_ANY, ofp.OFPG_ANY, 0, match, [])
        dp.send_msg(flow_mod)

    def fluxID(self, in_port, eth_dst, eth_src, eth_type, ip_proto = 0, port_dst = 0):
        el = [str(in_port), '/', eth_src, "<>", eth_dst, ":", str(port_dst), ",", str(ip_proto)]
        w = ''.join(el)
        return hashlib.md5(w.encode()).hexdigest()

    def getMatchAndFluxID(self, parser, in_port, eth_dst, eth_src, eth_type, ip_proto = 0, port_dst = 0):
        match_parameters = {'in_port' : in_port, 'eth_dst' : eth_dst, 'eth_src' : eth_src, 'eth_type' : eth_type, 'ip_proto' : ip_proto}

        port_parameter = 'tcp_dst'
        if ip_proto == 17: port_parameter = 'udp_dst'
        match_parameters[port_parameter] = port_dst

        if port_dst == 0: del match_parameters[port_parameter]
        if ip_proto == 0: del match_parameters['ip_proto']

        match = parser.OFPMatch(**match_parameters)
        flux_id = self.fluxID(in_port, eth_dst, eth_src, eth_type, ip_proto, port_dst)
        return match, flux_id

    def parseDNSresponse(self, res):
        out = ''.join([c if ord(c) not in range(42) else '.' for c in res[12:-5]])[1:]
        end = out.find('..')
        return out[0:end] if end != -1 else out

    def __init__(self, *args, **kwargs):
        super(FirewallSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.flux = {}
        self.internetPort = 2
        self.DPI_data = {}
        self.watched_ports = [80, 443, 53]
        self.currentDNSLookup = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        print('installing table-miss flows on switch #' + str(datapath.id))
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.delete_flow(datapath, ofproto.OFPTT_ALL, parser.OFPMatch()) #delete all current flows
        #base rule is push to controller and resubmit to table 2
        #return;

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        inst += [parser.OFPInstructionGotoTable(table_id=2)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=parser.OFPMatch(), instructions=inst, table_id=0)
        datapath.send_msg(mod)

    @set_ev_cls(dpset.EventDP, MAIN_DISPATCHER)
    def datapath_change_handler(self, ev):
        if ev.enter: #new datapath registered to the controller
            datapath = ev.dp;
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto
            print("switch #" + str(datapath.id) + " joined")
            switch = api.get_switch(self, datapath.id)[0]
            ports = switch.ports

            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
            inst += [parser.OFPInstructionGotoTable(table_id=2)]

            for port in ports:
                for p in self.watched_ports:
                    if p == 53:
                        watch_match = parser.OFPMatch(in_port=int(port.port_no), eth_type=0x0800, ip_proto=17, udp_dst=p)
                    else:
                        watch_match = parser.OFPMatch(in_port=int(port.port_no), eth_type=0x0800, ip_proto=6, tcp_dst=p)
                    #self.add_flow(datapath,1,watch_match, None, None, 0, None)
                    mod = parser.OFPFlowMod(datapath=datapath, priority=1, match=watch_match, instructions=inst, table_id=0)
                    datapath.send_msg(mod)

            miss_len_cfg = parser.OFPSetConfig(datapath, ofproto_v1_3.OFPC_FRAG_MASK,MISS_SEND_LENGTH)
            datapath.send_msg(miss_len_cfg)
            print("OK")


    def add_flow(self, datapath, priority, match, actions, buffer_id=None, table_id = 2, idle_timeout=60):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if not actions: #drop
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        else: #other kind of action
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]

        mod_parameters = {'datapath' : datapath,
                          'priority' : priority,
                          'match' : match,
                          'instructions' : inst,
                          'table_id' : table_id,
                          'idle_timeout' : idle_timeout,
                          'command' : ofproto.OFPFC_ADD,
                          'flags' : ofproto.OFPFF_SEND_FLOW_REM}

        if buffer_id: mod_parameters['buffer_id'] = buffer_id
        if idle_timeout is None: del mod_parameters['idle_timeout']

        mod = parser.OFPFlowMod(**mod_parameters)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        #if ev.msg.msg_len < ev.msg.total_len:
        #    print("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        eth_type = eth.ethertype;
        hasData = False
        protocols = [] #list of protocols encapsulated in the packet
        ports = []
        #list protocols inside packet and check if it has a payload
        for p in pkt.protocols:
            if not isinstance(p, (bytes, bytearray)):
                if p.protocol_name:
                    if p.protocol_name == 'ipv4':
                        ip_proto = p.proto
                    protocols.append(p.protocol_name);
            else: hasData = True

        if 'udp' in protocols:
            _udp = pkt.get_protocol(udp.udp)
            ports = [_udp.src_port, _udp.dst_port]
            if 'ipv4' in protocols and 53 in ports and hasData:
                _ip = pkt.get_protocol(ipv4.ipv4)
                pktdata = pkt.protocols[-1]
                dns_query = self.parseDNSresponse(pktdata)
                print(_ip.src + ' made a DNS request for ' + dns_query)
                try:
                    lookup = socket.gethostbyname(dns_query)
                    print(lookup)
                    r.hset('qdns', lookup, dns_query)
                except:
                    print("COULD NOT RESOLVE " + dns_query)
       	if 'tcp' in protocols: #packet has tcp
            _tcp = pkt.get_protocol(tcp.tcp)
            ports = [_tcp.src_port, _tcp.dst_port]
            if 'ipv4' in protocols and _tcp.dst_port in self.watched_ports:
                _ip = pkt.get_protocol(ipv4.ipv4)

                dpiid = _ip.src + '->' + _ip.dst + ':' + str(_tcp.dst_port)
                self.DPI_data.setdefault(dpiid, 0)
                self.DPI_data[dpiid] = self.DPI_data[dpiid]+_ip.total_length
                r.hset('dpi', dpiid, self.DPI_data[dpiid])

                try:
                    with raise_on_timeout(0.3): # Timeout in 300 milliseconds
                        lookup = socket.gethostbyaddr(_ip.dst)
                    print(lookup)
                    r.hset('dns', _ip.dst, lookup[0])
                except OSError:
                    print("Could not gethostbyname in time")

                '''
                try:
                    lookup = socket.gethostbyaddr(_ip.dst)
                    print(lookup)
                    r.hset('dns', _ip.dst, lookup[0])
                except:
                    pass
                #print(protocols, ip.src, ip.dst, self.DPI_data)
                '''
        else:
            print(protocols, eth.dst)

        #CAM table learning
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid][eth.dst] if eth.dst in self.mac_to_port[dpid] else ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        #print(in_port, '->', out_port,protocols, dest_tcp_port)

        if out_port != ofproto.OFPP_FLOOD:
            #create OFPMatch instance and fluxID depending on protocols used
            parameters = [parser, in_port, eth.dst, eth.src, eth.ethertype]
            table_match = 0
            if 'ipv4' in protocols and ('tcp' in protocols or 'udp' in protocols):
                parameters += [6] if 'tcp' in protocols else [17]
                matched = False
                for i in range(2):
                    if ports[i] in self.watched_ports:
                        matched = True
                if matched:
                    #parameters += [ports[1]]
                    table_match = 2
            elif 'ipv4' in protocols and 'icmp' in protocols:
                parameters += [1]

            #parameters += [[ports]]
            match, flux_id = self.getMatchAndFluxID(*parameters)
            #throw the packet away if its already being handled by the switch
            #flux_id += ports[0]

            if flux_id in self.flux.keys() and table_match == 2:
                #print('not pushing flow because already did', flux_id, ports, protocols)
                return
            #push flow to switch and save its id
            #so that we can recompute its id anytime we get another packet_in
            #match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 2, match, actions, msg.buffer_id, table_id=table_match)
                self.flux[flux_id] = match;
                return
            else:
                self.add_flow(datapath, 2, match, actions, table_id=table_match)
                self.flux[flux_id] = match;

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        if out_port == ofproto.OFPP_FLOOD and eth.dst == 'ff:ff:ff:ff:ff:ff':
            print(msg.buffer_id, ofproto.OFP_NO_BUFFER)
            parameters = [parser, in_port, eth.dst, eth.src, eth.ethertype]
            match, flux_id = self.getMatchAndFluxID(*parameters)
            self.add_flow(datapath, 2, match, actions, table_id=0)
            self.flux[flux_id] = match;

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        '''
        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
        elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
        elif msg.reason == ofp.OFPRR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPRR_GROUP_DELETE:
            reason = 'GROUP DELETE'
        else:
            reason = 'unknown'
        '''

        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            #drop flows have timeout to not block the route indefinitely
            #deleting the fluxID from self.flux allows us to check them again for blocked protocols
            m = msg.match
            port_dst = m['tcp_dst'] if 'tcp_dst' in m else m['udp_dst'] if 'udp_dst' in m else 0
            ip_proto = m['ip_proto'] if 'ip_proto' in m else 0
            flux_id = self.fluxID(m['in_port'], m['eth_dst'], m['eth_src'], m['eth_type'], ip_proto, port_dst)
            if flux_id in self.flux.keys():
                del self.flux[flux_id]
            else:
                print('WARNING : Orphaned OFPFlowRemoved : ', flux_id)


