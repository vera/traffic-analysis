#!/usr/bin/env python3

# Copyright (C) 2020 Vera Clemens <mail@veraclemens.org>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import pyshark
import argparse
from distutils.version import LooseVersion
from pyshark.tshark.tshark import get_tshark_version

FROM_BROKER_TO_DEVICE_FILTER = "wpan.dst64 == 00:12:4b:00:04:13:3d:f0 and wpan.src64 == 00:12:4b:00:04:13:36:c1 and not icmpv6"
FROM_DEVICE_TO_BROKER_FILTER = "wpan.src64 == 00:12:4b:00:04:13:3d:f0 and wpan.dst64 == 00:12:4b:00:04:13:36:c1 and not icmpv6"
WPAN_ACKS_FILTER = "wpan.frame_type == 2"
ICMPV6_FILTER = "icmpv6"

def analyse_capture(cap):
  packet_bytes = {
    'WPAN': 0,
    '6LOWPAN': 0,
    'TCP': 0,
    'MQTT': 0,
    'Payload': { 'Slices': 0, 'Topics': 0, 'NETCONFFunctions': 0, 'RPCCounters': 0, 'SliceNumbers': 0, 'NETCONFParams': 0, 'Total': 0 },
    'Total': 0
    }
  packets = 0

  for packet in cap:
    packets += 1
    packet_bytes['Total'] += packet.__len__()

    if 'WPAN' in packet:
      header_length = 0

      # Caution: This program does not cover all cases, only the ones observed in the MUP captures.
      # E.g., it does not cover the case of enabled security.

      if packet.wpan.pan_id_compression == "1":
        header_length += 2
      else:
        header_length += 4

      if packet.wpan.dst_addr_mode == "0x00000003":
        header_length += 8
      elif packet.wpan.dst_addr_mode != None:
        print("WARNING: WPAN field 'dst_addr_mode' has unhandled value", packet.wpan.dst_addr_mode)

      if packet.wpan.src_addr_mode == "0x00000003":
        header_length += 8
      elif packet.wpan.src_addr_mode != None:
        print("WARNING: WPAN field 'src_addr_mode' has unhandled value", packet.wpan.src_addr_mode)

      for field in ['fcf', 'seq_no', 'fcs']:
        header_length += int(packet.wpan.get_field_value(field).size)

      packet_bytes['WPAN'] += header_length

    if '6LOWPAN' in packet:
      header_length = 0

      if packet['6lowpan'].pattern == "0x00000003" or packet['6lowpan'].pattern == "0x00000018":
        # IP header compression or First fragment

        if packet['6lowpan'].pattern == "0x00000018":
          header_length += 4 # For Pattern, Datagram size, Datagram tag

        # 1. LOWPAN_IPHC Encoding

        #   0                                       1
        #   0   1   2   3   4   5   6   7   8   9   0   1   2   3   4   5
        # +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
        # | 0 | 1 | 1 |  TF   |NH | HLIM  |CID|SAC|  SAM  | M |DAC|  DAM  |
        # +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
        # Source: https://tools.ietf.org/html/rfc6282, Figure 2: LOWPAN_IPHC base Encoding
        header_length += 2

        if packet['6lowpan'].get_field_value('iphc_cid', raw=True) == '1':
          #   0   1   2   3   4   5   6   7
          # +---+---+---+---+---+---+---+---+
          # |      SCI      |      DCI      |
          # +---+---+---+---+---+---+---+---+
          # Source: https://tools.ietf.org/html/rfc6282, Figure 3: LOWPAN_IPHC Encoding
          header_length += 1

        # 2. In-line IP Fields

        if packet['6lowpan'].get_field_value('iphc_tf', raw=True) == '0':
          #                      1                   2                   3
          #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
          # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          # |ECN|   DSCP    |  rsv  |             Flow Label                |
          # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          # Source: https://tools.ietf.org/html/rfc6282, Figure 4: TF = 00: Traffic Class and Flow Label carried in-line
          header_length += 4
        elif packet['6lowpan'].get_field_value('iphc_tf', raw=True) == '1':
          #                      1                   2
          #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
          # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          # |ECN|rsv|             Flow Label                |
          # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          # Source: https://tools.ietf.org/html/rfc6282, Figure 5: TF = 01: Flow Label carried in-line
          header_length += 3
        elif packet['6lowpan'].get_field_value('iphc_tf', raw=True) == '10':
          #  0 1 2 3 4 5 6 7
          # +-+-+-+-+-+-+-+-+
          # |ECN|   DSCP    |
          # +-+-+-+-+-+-+-+-+
          # Source: https://tools.ietf.org/html/rfc6282, Figure 6: TF = 10: Traffic Class carried in-line
          header_length += 1

        if packet['6lowpan'].get_field_value('iphc_hlim', raw=True) == '0':
          header_length += 1
        
        # Caution: We are not covering all cases here, only the ones observed in the capture.
        # For information on other cases, see https://tools.ietf.org/html/rfc6282, pages 7-10

        if packet['6lowpan'].get_field_value('iphc_sac', raw=True) == '1' and packet['6lowpan'].get_field_value('iphc_sam', raw=True) == '1':
          header_length += 8
        elif packet['6lowpan'].get_field_value('iphc_sac', raw=True) == '1' and packet['6lowpan'].get_field_value('iphc_sam', raw=True) == '3':
          header_length += 0
        elif packet['6lowpan'].get_field_value('iphc_sac', raw=True) != None or packet['6lowpan'].get_field_value('iphc_sam', raw=True) != None:
          print("WARNING: 6LOWPAN field 'iphc_sac' has unhandled value", packet['6lowpan'].get_field_value('iphc_sac', raw=True))
          print("WARNING: 6LOWPAN field 'iphc_sam' has unhandled value", packet['6lowpan'].get_field_value('iphc_sam', raw=True))

        if packet['6lowpan'].get_field_value('iphc_m', raw=True) == '0' and packet['6lowpan'].get_field_value('iphc_dac', raw=True) == '1' and packet['6lowpan'].get_field_value('iphc_dam', raw=True) == '1':
          header_length += 8
        elif packet['6lowpan'].get_field_value('iphc_m', raw=True) == '0' and packet['6lowpan'].get_field_value('iphc_dac', raw=True) == '1' and packet['6lowpan'].get_field_value('iphc_dam', raw=True) == '3':
          header_length += 0
        elif packet['6lowpan'].get_field_value('iphc_m', raw=True) != None or packet['6lowpan'].get_field_value('iphc_dac', raw=True) != None or packet['6lowpan'].get_field_value('iphc_dam', raw=True) != None:
          print("WARNING: 6LOWPAN field 'iphc_m' has unhandled value", packet['6lowpan'].get_field_value('iphc_m', raw=True))
          print("WARNING: 6LOWPAN field 'iphc_dac' has unhandled value", packet['6lowpan'].get_field_value('iphc_dac', raw=True))
          print("WARNING: 6LOWPAN field 'iphc_dam' has unhandled value", packet['6lowpan'].get_field_value('iphc_dam', raw=True))

        # 3. LOWPAN_NHC Encoding

        if packet['6lowpan'].get_field_value('nhc_pattern') != None and packet['6lowpan'].nhc_pattern.binary_value[0] & b'\xF0'[0] == 224: # 11100000
          #   0   1   2   3   4   5   6   7
          # +---+---+---+---+---+---+---+---+
          # | 1 | 1 | 1 | 0 |    EID    |NH |
          # +---+---+---+---+---+---+---+---+
          # Source: https://tools.ietf.org/html/rfc6282, Figure 13: IPv6 Extension Header Encoding
          header_length += 1

          if packet['6lowpan'].get_field_value('nhc_ext_nh', raw=True) == '0':
            header_length += 1 # For "Next header" field

          if packet['6lowpan'].get_field_value('nhc_ext_length', raw=True) != None:
            header_length += 1 # For "Header length" field
            header_length += int(packet['6lowpan'].get_field_value('nhc_ext_length', raw=True))

      elif packet['6lowpan'].pattern == "0x0000001c":
        # Fragment
        header_length = 5

      else:
        print("WARNING: 6LOWPAN field 'pattern' has unhandled value", packet['6lowpan'].pattern)

      packet_bytes['6LOWPAN'] += header_length

    if 'TCP' in packet:
      header_length = int(packet.tcp.hdr_len.raw_value[0:1], 16) * 4
      packet_bytes['TCP'] += header_length

    if 'MQTT' in packet:
      # See: https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718019

      # 1. Fixed header

      header_length = 1 # For Header Flags
      header_length += len(packet['MQTT'].len.binary_value) # For Msg Len
      packet_bytes['MQTT'] += header_length

      # 2. Payload

      if int(packet['MQTT'].len) > 0:
        packet_bytes['Payload']['Total'] += int(packet['MQTT'].len)

        if int(packet['MQTT'].msgtype) == 3: # PUBLISH
          topic_bytes = 0
          if packet['MQTT'].get_field('property_len') is not None:
            topic_bytes += int(packet['MQTT'].property_len) + len(packet['MQTT'].property_len.binary_value)
          if packet['MQTT'].get_field('topic_len') is not None and int(packet['MQTT'].get_field('topic_len')) > 0:
            topic_bytes += len(packet['MQTT'].topic_len.binary_value) + len(packet['MQTT'].topic.binary_value)
          packet_bytes['Payload']['Topics'] += topic_bytes

          # Example messages:
          # 1. ASCII format:
          # - 470;PUB-UPDATE-IMAGE;459,0B6C13180420B75A6CCC5418E02D5015E06D024175B85910C0B46
          # - 470;OK
          # 2. Binary format:
          # - 399,qR`Ó2Maìì)kãwÁwº<Á¤vÉzáù7EÀõ7Éáwn
          # - 27;PUB-UPDATE-IMAGE;FIN

          try:
            # NOTE: packet['MQTT'].msg_text is only available starting from version 3.2.0 (see https://www.wireshark.org/docs/dfref/m/mqtt.html).
            mqtt_payload = str(packet['MQTT'].msg_text)
          except AttributeError:
            mqtt_payload = str(packet['MQTT'].msg)

          if mqtt_payload.find(';') >= 0 and (mqtt_payload.find(',') == -1 or mqtt_payload.find(';') < mqtt_payload.find(',')):
            semicolon_separated = mqtt_payload.split(';')
            if len(semicolon_separated) == 3:
              packet_bytes['Payload']['RPCCounters'] += len(semicolon_separated[0]) + 1 # + 1 for the semicolon itself
              packet_bytes['Payload']['NETCONFFunctions'] += len(semicolon_separated[1]) + 1 # + 1 for the semicolon itself
              comma_separated = semicolon_separated[2].split(',', 1)
              if len(comma_separated) == 2:
                packet_bytes['Payload']['SliceNumbers'] += len(comma_separated[0]) + 1 # + 1 for the comma itself
                packet_bytes['Payload']['Slices'] += len(comma_separated[1])
              else:
                packet_bytes['Payload']['NETCONFParams'] += len(semicolon_separated[2])
            elif len(semicolon_separated) == 2:
              packet_bytes['Payload']['RPCCounters'] += len(semicolon_separated[0]) + 1 # + 1 for the semicolon itself
              packet_bytes['Payload']['NETCONFParams'] += len(semicolon_separated[1])
          else:
            comma_separated = mqtt_payload.split(',', 1)
            if len(comma_separated) == 2 and comma_separated[0].isnumeric():
              packet_bytes['Payload']['SliceNumbers'] += len(comma_separated[0]) + 1 # + 1 for the comma itself
              packet_bytes['Payload']['Slices'] += int(packet['MQTT'].len) - topic_bytes - (len(comma_separated[0]) + 1)
            else:
              print("WARNING: MQTT payload of frame " + packet.number + " has unhandled format")
        else:
          print("WARNING: Unhandled MQTT message type", packet['MQTT'].msgtype)

  return (packet_bytes, packets)

def print_bytes(bytes, level=0):
  for key in bytes.keys():
    if type(bytes[key]) == dict:
      print(key + ":")
      print_bytes(bytes[key], level + 1)
    elif bytes[key] > 0:
      if key == 'Total':
        print('  ' * level + '-' * (35 - 2*level))
      print("  " * level + key + ":\t" + ('' if len(key) > 12 else '\t' if len(key) > 6-2*level else '\t\t'), bytes[key]/1000, "kB")

def print_analysis(bytes, packets):
  print("Packets:\t\t", packets)
  print()
  print_bytes(bytes)

def check_total(bytes):
  total_check = bytes['WPAN'] + bytes['6LOWPAN'] + bytes['TCP'] + bytes['MQTT'] + bytes['Payload']['Total']
  if total_check != bytes['Total']:
    print('\nWARNING: Total bytes do not add up to', bytes['Total'], 'bytes')
    print('Calculated total is', total_check, 'bytes')
    print('Difference:', total_check - bytes['Total'], 'bytes')

  payload_total_check = bytes['Payload']['Slices'] + bytes['Payload']['Topics'] + bytes['Payload']['NETCONFFunctions'] + bytes['Payload']['RPCCounters'] + bytes['Payload']['SliceNumbers'] + bytes['Payload']['NETCONFParams']
  if payload_total_check != bytes['Payload']['Total']:
    print('\nWARNING: Total payload bytes do not add up to', bytes['Payload']['Total'], 'bytes')
    print('Calculated total is', payload_total_check, 'bytes')
    print('Difference:', payload_total_check - bytes['Payload']['Total'], 'bytes')

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--pcap', help="path to pcap file" , type=str, required=True, default="trace.pcap")
  parser.add_argument('--tshark', help="path to tshark binary" , type=str, required=False)
  parser.add_argument('--mqtt-version', help="MQTT version to assume when parsing packets (possible options: 3.1, 3.1.1, 5.0)", type=str, required=False)
  parser.add_argument('--check-total', help="check if protocol bytes add up to total frame bytes",  dest='check_total', action='store_true')
  parser.set_defaults(check_total=False)
  args = parser.parse_args()

  # NOTE: The preference "mqtt.default_version" is only available starting from tshark version 3.3.0. Earlier versions of tshark will crash when the preference is set.
  if (get_tshark_version(args.tshark) < LooseVersion("3.3.0")):
    args.mqtt_version = None

  cap = pyshark.FileCapture(args.pcap, tshark_path=args.tshark, display_filter=FROM_BROKER_TO_DEVICE_FILTER, override_prefs={ 'mqtt.default_version': 'MQTT v' + args.mqtt_version } if args.mqtt_version else {})

  print("Using tshark binary at", cap._get_tshark_path(), "(version: " + str(cap._get_tshark_version()) + ")")

  print()
  print("####################")
  print("# Broker → Device: #")
  print("####################")
  print()
  bytes_from_broker_to_device, packets_from_broker_to_device = analyse_capture(cap)
  cap.close()
  print_analysis(bytes_from_broker_to_device, packets_from_broker_to_device)
  if args.check_total:
    check_total(bytes_from_broker_to_device)

  print()
  print("####################")
  print("# Device → Broker: #")
  print("####################")
  print()
  cap = pyshark.FileCapture(args.pcap, tshark_path=args.tshark, display_filter=FROM_DEVICE_TO_BROKER_FILTER, override_prefs={ 'mqtt.default_version': 'MQTT v' + args.mqtt_version } if args.mqtt_version else {})
  bytes_from_device_to_broker, packets_from_device_to_broker = analyse_capture(cap)
  cap.close()
  print_analysis(bytes_from_device_to_broker, packets_from_device_to_broker)
  if args.check_total:
    check_total(bytes_from_device_to_broker)

  print()
  print("####################")
  print()

  cap = pyshark.FileCapture(args.pcap, tshark_path=args.tshark, display_filter=WPAN_ACKS_FILTER)
  wpan_acks_total_bytes = 0
  for packet in cap:
    wpan_acks_total_bytes += int(packet.length)
  cap.close()
  print("IEEE 802.15.4 ACKs:\t", wpan_acks_total_bytes/1000, "kB")

  cap = pyshark.FileCapture(args.pcap, tshark_path=args.tshark, display_filter=ICMPV6_FILTER)
  icmpv6_total_bytes = 0
  for packet in cap:
    icmpv6_total_bytes += int(packet.length)
  cap.close()
  print("ICMPv6:\t\t\t", icmpv6_total_bytes/1000, "kB")

if __name__ == "__main__":
  main()
