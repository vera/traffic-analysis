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

import re

class MynoAnalyser:
  def __init__(self):
    self.bytes = { 'slices': 0,
                   'netconf_functions': 0,
                   'rpc_counters': 0,
                   'slice_numbers': 0,
                   'netconf_params': 0,
                   'total': 0 }
    self.packets = 0

  def reset(self):
    self.bytes = { 'slices': 0,
                   'netconf_functions': 0,
                   'rpc_counters': 0,
                   'slice_numbers': 0,
                   'netconf_params': 0,
                   'total': 0 }
    self.packets = 0

  def add(self, mqtt, topic_bytes):
    self.packets += 1
    self.bytes['total'] += int(mqtt.len) - topic_bytes

    # Example messages:
    # 1. ASCII format:
    # - 470;PUB-UPDATE-IMAGE;459,0B6C13180420B75A6CCC5418E02D5015E06D024175B85910C0B46
    # - 470;OK
    # 2. Binary format:
    # - 399,qR`Ó2Maìì)kãwÁwº<Á¤vÉzáù7EÀõ7Éáwn
    # - 27;PUB-UPDATE-IMAGE;FIN

    try:
      # NOTE: packet['MQTT'].msg_text is only available starting from version 3.2.0 (see https://www.wireshark.org/docs/dfref/m/mqtt.html).
      double_semicolon_separated = re.match('^([0-9]+;)([a-zA-Z-]+;)([0-9a-zA-Z,]+)$', mqtt.msg_text)
      single_semicolon_separated = re.match('^([0-9]+;)([0-9a-zA-Z,-]+)$', mqtt.msg_text)
      comma_separated = re.match('^([0-9]+,)(.*)$', mqtt.msg_text)
    except AttributeError:
      double_semicolon_separated = re.match('^([0-9]+;)([a-zA-Z-]+;)([0-9a-zA-Z,]+)$', mqtt.msg)
      single_semicolon_separated = re.match('^([0-9]+;)([0-9a-zA-Z,-]+)$', mqtt.msg)
      comma_separated = re.match('^([0-9]+,)(.*)$', mqtt.msg)

    if double_semicolon_separated:
      self.bytes['rpc_counters'] += len(double_semicolon_separated.group(1))
      self.bytes['netconf_functions'] += len(double_semicolon_separated.group(2))
      comma_separated = re.match('^([0-9]+,)(.*)$', double_semicolon_separated.group(3))
      if comma_separated:
        self.bytes['slice_numbers'] += len(comma_separated.group(1))
        self.bytes['slices'] += len(comma_separated.group(2))
      else:
        self.bytes['netconf_params'] += len(double_semicolon_separated.group(3))
    elif single_semicolon_separated:
      self.bytes['rpc_counters'] += len(single_semicolon_separated.group(1))
      self.bytes['netconf_functions'] += len(single_semicolon_separated.group(2))
    elif comma_separated:
      self.bytes['slice_numbers'] += len(comma_separated.group(1))
      self.bytes['slices'] += int(mqtt.len) - topic_bytes - len(comma_separated.group(1))
    else:
      try:
        # NOTE: packet['MQTT'].msg_text is only available starting from version 3.2.0 (see https://www.wireshark.org/docs/dfref/m/mqtt.html).
        print("WARNING: MQTT payload has unhandled format", mqtt.msg_text)
      except AttributeError:
        print("WARNING: MQTT payload has unhandled format", mqtt.msg)