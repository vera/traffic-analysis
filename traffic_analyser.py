#!/usr/bin/env python3

# Copyright (C) 2020-2021 Vera Clemens <mail@veraclemens.org>

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

import argparse
from functools import reduce

import pyshark
from distutils.version import LooseVersion
from pyshark.tshark.tshark import get_tshark_version

import analysers

WPAN_ACKS_FILTER = "wpan.frame_type == 2"
ICMPV6_FILTER = "icmpv6"

class TrafficAnalyser:
  def __init__(self, args):
    self.args = args
    self.override_prefs = { 'mqtt.default_version': 'MQTT v' + args.mqtt_version } if args.mqtt_version else {}
    self.analysers = {}

    if self.args.payload_analyser:
      self.analysers['payload'] = getattr(analysers, "{}Analyser".format(self.args.payload_analyser.capitalize()))()

  def load_capture(self, pcap, device_to_server):
    if device_to_server:
      display_filter = "wpan.src64 == {} and wpan.dst64 == {} and not icmpv6".format(self.args.device_addr, self.args.server_addr)
    else:
      display_filter = "wpan.dst64 == {} and wpan.src64 == {} and not icmpv6".format(self.args.device_addr, self.args.server_addr)

    self.cap = pyshark.FileCapture(pcap, tshark_path=self.args.tshark,
                                   display_filter=display_filter,
                                   override_prefs=self.override_prefs)

  def close_capture(self):
    self.cap.close()

  def _reset(self, analysers):
    for analyser in analysers:
      if isinstance(analyser, dict):
        self._reset(analyser.values())
      else:
        analyser.reset()

  def reset(self):
    self._reset(self.analysers.values())

  def analyse_capture(self):
    self.bytes = { 'total': 0 }

    self.packets = 0
    unhandled_layers = []

    for packet in self.cap:
      self.packets += 1
      self.bytes['total'] += packet.__len__()

      layers = packet.layers

      skip_layers = ['data']
      if ('ipv6' in map((lambda x: x.layer_name), packet.layers) and
          '6lowpan' in map((lambda x: x.layer_name), packet.layers)):
        skip_layers.append('ipv6') # to avoid counting bytes twice

      for layer in layers:
        if layer.layer_name in skip_layers:
          continue

        if layer.layer_name[0].isdigit():
          layer_name = layer.layer_name[1:]
        else:
          layer_name = layer.layer_name

        if not layer_name in self.analysers:
          try:
            analyser_class = getattr(analysers, "{}Analyser".format(layer_name.capitalize()))

            # TODO there must be a better way to do this
            if 'app_layer' in analyser_class.__module__:
              if 'payload' in self.analysers:
                self.analysers[layer_name] = analyser_class(self.analysers['payload'])
              else:
                self.analysers[layer_name] = analyser_class(None)
                self.analysers['payload_' + layer_name] = self.analysers[layer_name].payload_analyser
            else:
              self.analysers[layer_name] = analyser_class()
          except AttributeError:
            if layer.layer_name not in unhandled_layers:
              unhandled_layers.append(layer.layer_name)
            continue
        
        self.analysers[layer_name].add(layer)

    self.bytes.update(self._collect_bytes(self.analysers))

    if len(unhandled_layers) > 0:
      print('WARNING: Unhandled layers: {}\n'.format(', '.join(unhandled_layers)))

  def _collect_bytes(self, analysers):
    bytes = {}

    for layer_name in analysers:
      if isinstance(analysers[layer_name], dict):
        bytes[layer_name] = self._collect_bytes(analysers[layer_name])
      else:
        bytes[layer_name] = analysers[layer_name].bytes

    return bytes

  def _print_bytes(self, bytes, level=0):
    for key in sorted(bytes.keys(), key=(lambda x: x == 'total')):
      printable_key = key.replace('_', ' ').capitalize()
      if type(bytes[key]) == dict:
        print(printable_key + ":")
        self._print_bytes(bytes[key], level + 1)
      elif bytes[key] > 0:
        if key == 'total':
          print('  ' * level + '-' * (35 - 2*level))
        print("  " * level + printable_key + ":\t" + ('' if len(key) > 12 else '\t' if len(key) > 6-2*level else '\t\t'), bytes[key]/1000, "kB")

  def print_analysis(self):
    print("Packets:\t\t", self.packets)
    self._print_bytes(self.bytes)

  def _add_bytes(self, bytes):
    totals = []
    total = 0

    for key in bytes:
      if key == 'total':
        continue
      elif isinstance(bytes[key], int):
        total += bytes[key]
      elif isinstance(bytes[key], dict) and 'total' in bytes[key]:
        total += bytes[key]['total']
        totals += self._add_bytes(bytes[key])

    if 'total' in bytes:
      totals.append((total, bytes['total']))
    return totals

  def check_totals(self):
    totals = self._add_bytes(self.bytes)

    for (actual, expected) in totals:
      if actual != expected:
        print('\nWARNING: calculated total of {} bytes != expected total of {} bytes ({} bytes)'.format(actual, expected, actual - expected))

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--pcap', help="path to pcap file" , type=str, required=True, default="trace.pcap")
  parser.add_argument('--server-addr', help="IP address of the server" , type=str, required=True)
  parser.add_argument('--device-addr', help="IP address of the device" , type=str, required=True)
  parser.add_argument('--tshark', help="path to tshark binary" , type=str, required=False)
  parser.add_argument('--mqtt-version', help="MQTT version to assume when parsing packets (possible options: 3.1, 3.1.1, 5.0)", type=str, required=False)
  parser.add_argument('--check-totals', help="check if bytes correctly add up to the totals",  dest='check_totals', action='store_true')
  parser.add_argument('--payload-analyser', help="name of module for payload analysis", type=str, required=False)
  parser.set_defaults(check_totals=False)
  args = parser.parse_args()

  print("Using tshark version {}".format(get_tshark_version(args.tshark)))

  # NOTE: The preference "mqtt.default_version" is only available starting from tshark version 3.3.0. Earlier versions of tshark will crash when the preference is set.
  if get_tshark_version(args.tshark) < LooseVersion("3.3.0"):
    args.mqtt_version = None

  analyser = TrafficAnalyser(args)

  print()
  print("####################")
  print("# Server → Device: #")
  print("####################")
  print()
  analyser.load_capture(args.pcap, False)
  analyser.analyse_capture()
  analyser.close_capture()
  analyser.print_analysis()
  if args.check_totals:
    analyser.check_totals()

  print()
  print("####################")
  print("# Device → Server: #")
  print("####################")
  print()
  analyser.reset()
  analyser.load_capture(args.pcap, True)
  analyser.analyse_capture()
  analyser.close_capture()
  analyser.print_analysis()
  if args.check_totals:
    analyser.check_totals()

if __name__ == "__main__":
  main()