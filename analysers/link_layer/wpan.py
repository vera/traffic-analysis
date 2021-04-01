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

class WpanAnalyser:
  def __init__(self):
    self.bytes = 0
    self.packets = 0

  def reset(self):
    self.bytes = 0
    self.packets = 0

  def add(self, wpan):
    self.packets += 1

    # Caution: This does not cover all cases.
    # For example, it does not cover the case of enabled security.

    if wpan.pan_id_compression == "1":
      self.bytes += 2
    else:
      self.bytes += 4

    if wpan.dst_addr_mode == "0x00000003":
      self.bytes += 8
    elif wpan.dst_addr_mode != None:
      print("WARNING: WPAN field 'dst_addr_mode' has unhandled value", wpan.dst_addr_mode)

    if wpan.src_addr_mode == "0x00000003":
      self.bytes += 8
    elif wpan.src_addr_mode != None:
      print("WARNING: WPAN field 'src_addr_mode' has unhandled value", wpan.src_addr_mode)

    for field in ['fcf', 'seq_no', 'fcs']:
      self.bytes += int(wpan.get_field_value(field).size)