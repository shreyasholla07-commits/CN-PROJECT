"""
Dynamic Host Blocking System (DHBS) - Ryu OpenFlow 1.3 controller app.

Idea: learning switch + monitor TCP connection rate (SYN packet-ins) and
flow statistics per source host. If a host crosses a threshold, install a
high-priority DROP rule (SDN flow rule) on every switch and keep the host in
a dynamic blocklist. The block expires automatically (hard_timeout).
Run:  ryu-manager dynamic_blocker.py
"""
import os, time, csv, collections
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (CONFIG_DISPATCHER, MAIN_DISPATCHER,
                                    DEAD_DISPATCHER, set_ev_cls)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, ether_types
from ryu.lib import hub

# ---------------- Configurable thresholds (env vars override) -------------
WINDOW         = float(os.environ.get('WINDOW', 5))          # seconds
CONN_THRESHOLD = int(os.environ.get('CONN_THRESHOLD', 20))   # new TCP conns / WINDOW
PPS_THRESHOLD  = float(os.environ.get('PPS_THRESHOLD', 2000))# packets/sec per host
POLL_INTERVAL  = float(os.environ.get('POLL_INTERVAL', 2))   # flow-stats polling
BLOCK_TIME     = int(os.environ.get('BLOCK_TIME', 60))       # seconds (hard_timeout)
WHITELIST      = set(os.environ.get('WHITELIST', '10.0.0.1').split(','))  # server
LOG_FILE       = os.environ.get('BLOCK_LOG', 'logs/blocker_events.csv')

PRIO_MISS, PRIO_L2, PRIO_FLOW, PRIO_BLOCK = 0, 1, 10, 100


class DynamicHostBlocker(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}                          # dpid -> {mac: port}
        self.datapaths = {}                            # dpid -> datapath
        self.syn_times = collections.defaultdict(collections.deque)  # ip -> SYN timestamps
        self.blocklist = {}                            # ip -> expiry time
        self.last_pkts = {}                            # per-flow last packet count
        os.makedirs(os.path.dirname(LOG_FILE) or '.', exist_ok=True)
        self.logf = open(LOG_FILE, 'w', newline='')
        self.csv = csv.writer(self.logf)
        self.csv.writerow(['time', 'event', 'ip', 'reason', 'value'])
        self.logf.flush()
        self.monitor = hub.spawn(self._monitor)        # stats polling thread
        self.logger.info("DHBS started: conn>%s/%ss pps>%s block=%ss whitelist=%s",
                         CONN_THRESHOLD, WINDOW, PPS_THRESHOLD, BLOCK_TIME, WHITELIST)

    # ---------------- logging ----------------
    def _log(self, event, ip, reason='', value=''):
        self.csv.writerow([time.strftime('%H:%M:%S'), event, ip, reason, value])
        self.logf.flush()
        self.logger.warning("%s %s %s %s", event, ip, reason, value)

    # ---------------- switch connect ----------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _features(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, PRIO_MISS, parser.OFPMatch(), actions)   # table-miss

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        else:
            self.datapaths.pop(dp.id, None)

    def _add_flow(self, dp, prio, match, actions, idle=0, hard=0, flags=0):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] if actions else []
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=prio, match=match,
                                      instructions=inst, idle_timeout=idle,
                                      hard_timeout=hard, flags=flags))

    # ---------------- packet-in: switching + connection-rate monitor -------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        ip = pkt.get_protocol(ipv4.ipv4)
        t = pkt.get_protocol(tcp.tcp)

        if ip and ip.src in self.blocklist:            # safety net: drop
            return

        self.mac_to_port.setdefault(dp.id, {})[eth.src] = in_port
        out_port = self.mac_to_port[dp.id].get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if ip and t:
            # a pure SYN (SYN=1, ACK=0) = a NEW connection attempt
            if (t.bits & tcp.TCP_SYN) and not (t.bits & tcp.TCP_ACK):
                if self._record_syn(ip.src):
                    return                              # host just blocked
            if out_port != ofp.OFPP_FLOOD:
                # per-connection (5-tuple) flow => every new connection
                # produces one packet-in, which gives us the connection rate
                match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ip_proto=6,
                                        ipv4_src=ip.src, ipv4_dst=ip.dst,
                                        tcp_src=t.src_port, tcp_dst=t.dst_port)
                self._add_flow(dp, PRIO_FLOW, match, actions, idle=5)
        elif out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst)
            self._add_flow(dp, PRIO_L2, match, actions, idle=30)

        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                        in_port=in_port, actions=actions, data=data))

    def _record_syn(self, src):
        """Sliding-window counter. Returns True if src was blocked now."""
        if src in WHITELIST or src in self.blocklist:
            return False
        now = time.time()
        dq = self.syn_times[src]
        dq.append(now)
        while dq and now - dq[0] > WINDOW:
            dq.popleft()
        if len(dq) > CONN_THRESHOLD:
            self._block(src, 'conn_rate', "%d SYN in %ss" % (len(dq), WINDOW))
            return True
        return False

    # ---------------- blocking ----------------
    def _block(self, ip, reason, value):
        if ip in self.blocklist or ip in WHITELIST:
            return
        self.blocklist[ip] = time.time() + BLOCK_TIME
        for dp in self.datapaths.values():              # install DROP on all switches
            ofp, parser = dp.ofproto, dp.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
            self._add_flow(dp, PRIO_BLOCK, match, [], hard=BLOCK_TIME,
                           flags=ofp.OFPFF_SEND_FLOW_REM)  # empty actions = DROP
        self._log('BLOCK', ip, reason, value)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed(self, ev):                         # block rule expired
        msg = ev.msg
        if msg.priority != PRIO_BLOCK:
            return
        ip = msg.match.get('ipv4_src')
        if ip in self.blocklist:
            del self.blocklist[ip]
            self.syn_times.pop(ip, None)                 # fresh start
            self._log('UNBLOCK', ip, 'block expired', '%ss' % BLOCK_TIME)

    # ---------------- flow statistics ----------------
    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            hub.sleep(POLL_INTERVAL)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _stats_reply(self, ev):
        dpid = ev.msg.datapath.id
        per_src, cur = collections.defaultdict(int), {}
        for st in ev.msg.body:
            if st.priority != PRIO_FLOW:
                continue
            src = st.match.get('ipv4_src')
            if src is None:
                continue
            key = (dpid, src, st.match.get('ipv4_dst'),
                   st.match.get('tcp_src'), st.match.get('tcp_dst'))
            cur[key] = st.packet_count
            per_src[src] += st.packet_count - self.last_pkts.get(key, 0)
        self.last_pkts = {k: v for k, v in self.last_pkts.items() if k[0] != dpid}
        self.last_pkts.update(cur)
        for src, pk in per_src.items():
            pps = pk / POLL_INTERVAL
            self.logger.debug("stats %s %.1f pps", src, pps)
            if pps > PPS_THRESHOLD:
                self._block(src, 'pps', "%.0f pps" % pps)
