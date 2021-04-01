# Example usage

To analyse a pcap file containing traffic between device and server, specify its path and the IP addresses:

`./pcap_analysis.py --pcap trace-mup-PUB-UPDATE-IMAGE.pcap --device-addr 00:12:4b:00:04:13:3d:f0 --broker-addr 00:12:4b:00:04:13:36:c1`

To analyse application layer payloads, additionally specify the name of a payload analyser module to use:

`--payload-analyser myno`

To use a specific tshark binary and MQTT version, additionally specify the binary's path and the version:

`--tshark /home/vagrant/iot/wireshark-3.3.0rc0-1711-gc099892700eb/build/run/tshark --mqtt-version 5.0`

Caution: The preference "mqtt.default_version" is only available starting from tshark version 3.3.0. When using an older version of wireshark, this option will have no effect.
Prior to version 3.3.0, tshark learned the MQTT version from the MQTT CONNECT message. See: https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=16722

To optionally check whether all parts of the analysis sum up to the correct total, use the option "--check-total":

`./pcap_analysis.py --pcap trace-mup.pcap --check-total`

Note: Differences from the expected total may occur when the trace file captured some kind of "transmission error", e.g., a missing fragment, or an unexpected type of packet the script is unable to handle.
In the case of an unexpected type of packet, the script may additionally print a WARNING (e.g., "WARNING: Unhandled MQTT message type").

# Options

```
usage: traffic_analyser.py [-h] --pcap PCAP --server-addr SERVER_ADDR --device-addr DEVICE_ADDR
                           [--tshark TSHARK] [--mqtt-version MQTT_VERSION] [--check-total]
                           [--payload-analyser PAYLOAD_ANALYSER]

optional arguments:
  -h, --help            show this help message and exit
  --pcap PCAP           path to pcap file
  --server-addr SERVER_ADDR
                        IP address of the server
  --device-addr DEVICE_ADDR
                        IP address of the device
  --tshark TSHARK       path to tshark binary
  --mqtt-version MQTT_VERSION
                        MQTT version to assume when parsing packets (possible options: 3.1,
                        3.1.1, 5.0)
  --check-total         check if protocol bytes add up to total frame bytes
  --payload-analyser PAYLOAD_ANALYSER
                        name of module for payload analysis
```
