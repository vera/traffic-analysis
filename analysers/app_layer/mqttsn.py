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

from analysers.custom_payload.default_mqttsn import DefaultMqttsnPayloadAnalyser

class MqttsnAnalyser:
  def __init__(self, payload_analyser):
    self.bytes = 0
    self.packets = 0
    if payload_analyser:
      self.payload_analyser = payload_analyser
    else:
      self.payload_analyser = DefaultMqttsnPayloadAnalyser()

  def reset(self):
    self.bytes = 0
    self.packets = 0

  def add(self, mqttsn):
    self.packets += 1

    if int(mqttsn.msg_type) == 10: # REGISTER
      topic_bytes = int(mqttsn.msg_len) - 6
      self.bytes += 6
      self.payload_analyser.add(mqttsn, topic_bytes)
    elif int(mqttsn.msg_type) == 12: # PUBLISH
      self.bytes += 7
      self.payload_analyser.add(mqttsn, 0)
    elif int(mqttsn.msg_type) == 18: # SUBSCRIBE
      topic_bytes = int(mqttsn.msg_len) - 5
      self.bytes += 5
      self.payload_analyser.add(mqttsn, topic_bytes)
    else:
      self.bytes += int(mqttsn.msg_len)