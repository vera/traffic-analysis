# Copyright (C) 2021 Vera Clemens <mail@veraclemens.org>

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

class DefaultMqttsnPayloadAnalyser:
  def __init__(self):
    self.bytes = { 'topics': 0, 'messages': 0, 'total': 0 }
    self.packets = 0

  def reset(self):
    self.bytes = { 'topics': 0, 'messages': 0, 'total': 0 }
    self.packets = 0

  def add(self, mqttsn, topic_bytes):
    self.packets += 1

    if int(mqttsn.msg_type) == 10: # REGISTER
      self.bytes['topics'] += topic_bytes
      self.bytes['total'] += topic_bytes
    elif int(mqttsn.msg_type) == 12: # PUBLISH
      self.bytes['messages'] += int(mqttsn.msg_len) - 7
      self.bytes['total'] += int(mqttsn.msg_len) - 7
    elif int(mqttsn.msg_type) == 18: # SUBSCRIBE
      self.bytes['topics'] += topic_bytes
      self.bytes['total'] += topic_bytes