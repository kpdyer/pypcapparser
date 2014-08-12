pypcapparser
============

a pcap-parsing library

### Example Usage

```python
import pypcapparser

extracted_streams = pypcapparser.process_pcap(filename="test.pcap",
                                              protocols=[pypcapparser.TCP],
                                              dports=pypcapparser.HTTP_PORTS)

for stream in extracted_streams:
    print stream
```

### Data Structure

```
[
  {
    'clientServerMessages': ['GET /..', 'GET /...'],
    'serverClientMessages': ['HTTP/1.1...', 'HTTP/1.0...'],
    'sessionStart': [start time of session (epoch)],
    'sessionEnd': [end time of session (epoch)],
  },
  {
    ...
  }
]
```
