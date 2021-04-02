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

from analysers.custom_payload.default_mqtt import DefaultMqttPayloadAnalyser

class MqttAnalyser:
  def __init__(self, payload_analyser):
    self.bytes = 0
    self.packets = 0
    if payload_analyser:
      self.payload_analyser = payload_analyser
    else:
      self.payload_analyser = DefaultMqttPayloadAnalyser()

  def reset(self):
    self.bytes = 0
    self.packets = 0

  def add(self, mqtt):
    self.packets += 1

    # See: https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718019

    # 1. Fixed header

    header_bytes = 1 # For Header Flags
    header_bytes += len(mqtt.len.binary_value) # For Msg Len

    # 2. Payload

    topic_bytes = 0
    if int(mqtt.len) > 0:
      if int(mqtt.msgtype) == 3: # PUBLISH
        if mqtt.get_field('property_len') is not None:
          topic_bytes += int(mqtt.property_len) + len(mqtt.property_len.binary_value)
        if mqtt.get_field('topic_len') is not None and int(mqtt.get_field('topic_len')) > 0:
          topic_bytes += len(mqtt.topic_len.binary_value) + len(mqtt.topic.binary_value)

        self.payload_analyser.add(mqtt, topic_bytes)
      else:
        print("WARNING: Unhandled MQTT message type", mqtt.msgtype)

      self.bytes += header_bytes