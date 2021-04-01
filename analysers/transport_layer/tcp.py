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

class TcpAnalyser:
  def __init__(self):
    self.bytes = 0
    self.packets = 0

  def reset(self):
    self.bytes = 0
    self.packets = 0

  def add(self, tcp):
    self.packets += 1

    self.bytes += int(tcp.hdr_len.raw_value[0:1], 16) * 4