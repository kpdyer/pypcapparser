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
