#! /usr/bin/env python2

import nids

TCP = "tcp"
HTTP_PORTS = [80, 8080]

NOTROOT = "nobody"   # edit to taste
end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)
streams_ = []
dports_ = []
session_start_ = -1
session_end_ = -1

def handleTcpStream(tcp):
    global streams_, session_start_, session_end_

    if tcp.nids_state == nids.NIDS_JUST_EST:
        # new to us, but do we care?
        session_start_ = nids.get_pkt_ts()
        ((src, sport), (dst, dport)) = tcp.addr
        if not dports_ or dport in dports_:
            tcp.client.collect = 1
            tcp.server.collect = 1
    elif tcp.nids_state == nids.NIDS_DATA:
        # keep all of the stream's new data
    	tcp.discard(0)
    elif tcp.nids_state in end_states:
        session_end_ = nids.get_pkt_ts()
        streams_.append({'clientServerMessages': [tcp.server.data[:tcp.server.count]],
                         'serverClientMessages': [tcp.client.data[:tcp.client.count]],
                         'sessionStart': session_start_,
                         'sessionEnd': session_end_})

    return streams_

def process_pcap(filename, protocols=[], dports=[]):
    global streams_, dports_
    streams_ = []
    dports_ = dports

    nids.param("scan_num_hosts", 0)         # disable portscan detection
    nids.chksum_ctl([('0.0.0.0/0', False)]) # disable checksumming
    nids.param("filename", filename)        # specify pcap file to parse
    nids.init()

    if not protocols or TCP in protocols:
        nids.register_tcp(handleTcpStream)

    # Loop forever (network device), or until EOF (pcap file)
    # Note that an exception in the callback will break the loop!
    try:
        nids.run()
    except nids.error, e:
        print "nids/pcap error:", e
    except Exception, e:
        print "misc. exception (runtime error in user callback?):", e

    return streams_
