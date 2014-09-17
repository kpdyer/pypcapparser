#! /usr/bin/env python2

import nids

from http_parser.parser import HttpParser

TCP = "tcp"
HTTP_PORTS = [80, 8080]

NOTROOT = "nobody"   # edit to taste
end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)
streams_ = []
dports_ = []
session_start_ = -1
session_end_ = -1

CONTENT_LENGTH_HEADER = 'Content-Length'

def parse_without_content_length(http_stream):
    http_message = http_stream.partition('\r\n\r\n')[0] + '\r\n\r\n'
    http_stream = http_stream.partition('\r\n\r\n')[2]
    return (http_message, http_stream)

def parse_with_content_length(http_stream):
    http_message_headers = http_stream.partition('\r\n\r\n')[0] + '\r\n\r\n'
    body = http_stream.partition('\r\n\r\n')[2]

    for http_header in http_message_headers.split('\n'):
        if http_header.startswith(CONTENT_LENGTH_HEADER):
            body_length = int(http_header.split(':')[1])

    http_message_body = body[:body_length]
    http_message = http_message_headers + http_message_body
    http_stream = body[body_length:]

    return (http_message, http_stream)

def is_content_length_in_message(http_stream):
    http_message = http_stream.partition('\r\n\r\n')[0]
    return (CONTENT_LENGTH_HEADER in http_message)

def get_first_message(http_stream):
    content_length_in_first_message = is_content_length_in_message(http_stream)
    if content_length_in_first_message:
        return parse_with_content_length(http_stream)
    else:
        return parse_without_content_length(http_stream)

def http_stream_to_array(http_stream):
    retval = []
    while http_stream != '':
        (http_message, http_stream) = get_first_message(http_stream)
        retval.append(http_message)
    return retval

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
        clientServerMessages = http_stream_to_array(tcp.server.data[:tcp.server.count])
        serverClientMessages = http_stream_to_array(tcp.client.data[:tcp.client.count])
        streams_.append({'clientServerMessages': clientServerMessages,
                         'serverClientMessages': serverClientMessages,
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
