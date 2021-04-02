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

from analysers.custom_payload.default_coap import DefaultCoapPayloadAnalyser

class CoapAnalyser:
  def __init__(self, payload_analyser):
    self.bytes = 0
    self.packets = 0
    if payload_analyser:
      self.payload_analyser = payload_analyser
    else:
      self.payload_analyser = DefaultCoapPayloadAnalyser()

  def reset(self):
    self.bytes = 0
    self.packets = 0

  def add(self, coap):
    self.packets += 1
    self.bytes += 4 + int(coap.token_len) # Version, Type, TKL, Code, MID, Token

    i = 0
    for opt in coap.opt_name.all_fields:
      self.bytes += 1 # Option Delta, Option Length
      if 'Uri-Path' in str(opt):
        self.payload_analyser.add(coap, int(coap.opt_length.all_fields[i].show), 0)
      else:
        self.bytes += coap.opt_length.all_fields[i].int_value
      i += 1

    if 'opt_delta_ext' in coap.field_names:
      for ode in coap.opt_delta_ext.all_fields:
        self.bytes += int(ode.size)

    if 'opt_length_ext' in coap.field_names:
      i = 0
      for ole in coap.opt_length_ext.all_fields:
        self.bytes += int(ole.size)
        self.payload_analyser.add(coap, int(coap.opt_length_ext.all_fields[i].show), 0)
        i += 1
      
    if 'opt_end_marker' in coap.field_names:
      self.bytes += 1
      if 'block_length' in coap.field_names:
        self.payload_analyser.add(coap, 0, int(coap.block_length))
      elif 'payload_length' in coap.field_names:
        self.payload_analyser.add(coap, 0, int(coap.payload_length))