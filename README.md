# Example usage

To analyse a pcap file, specify its path:

`./pcap_analysis.py --pcap trace-mup-PUB-UPDATE-IMAGE.pcap`

To use a specific tshark binary and MQTT version, specify the binary's path and the version:

`./pcap_analysis.py --pcap trace-mup-PUB-UPDATE-IMAGE.pcap --tshark /home/vagrant/iot/wireshark-3.3.0rc0-1711-gc099892700eb/build/run/tshark --mqtt-version 5.0`

Caution: The preference "mqtt.default_version" is only available starting from tshark version 3.3.0. When using an older version of wireshark, this option will have no effect.
Prior to version 3.3.0, tshark learned the MQTT version from the MQTT CONNECT message. See: https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=16722

To optionally check whether all parts of the analysis sum up to the correct total, use the option "--check-total":

`./pcap_analysis.py --pcap trace-mup.pcap --check-total`

Note: Differences from the expected total may occur when the trace file captured some kind of "transmission error", e.g., a missing fragment, or an unexpected type of packet the script is unable to handle.
In the case of an unexpected type of packet, the script may additionally print a WARNING (e.g., "WARNING: Unhandled MQTT message type").

# Options

```
--pcap		Specifies the path of the pcap file to be analyzed.

--check-total	(Optional) Specifies whether the program should perform a
		check whether the analysis results add up to the expected total.
		If not, this may indicate that the analysis program needs to be extended.

--tshark	(Optional) Specifies the path of the tshark binary to be used.
```
