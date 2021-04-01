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

class LowpanAnalyser:
  def __init__(self):
    self.bytes = 0
    self.packets = 0

  def reset(self):
    self.bytes = 0
    self.packets = 0

  def add(self, sixlowpan):
    self.packets += 1

    if sixlowpan.pattern == "0x00000003" or sixlowpan.pattern == "0x00000018":
      # IP header compression or First fragment

      if sixlowpan.pattern == "0x00000018":
        self.bytes += 4 # For Pattern, Datagram size, Datagram tag

      # 1. LOWPAN_IPHC Encoding

      #   0                                       1
      #   0   1   2   3   4   5   6   7   8   9   0   1   2   3   4   5
      # +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      # | 0 | 1 | 1 |  TF   |NH | HLIM  |CID|SAC|  SAM  | M |DAC|  DAM  |
      # +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      # Source: https://tools.ietf.org/html/rfc6282, Figure 2: LOWPAN_IPHC base Encoding
      self.bytes += 2

      if sixlowpan.get_field_value('iphc_cid', raw=True) == '1':
        #   0   1   2   3   4   5   6   7
        # +---+---+---+---+---+---+---+---+
        # |      SCI      |      DCI      |
        # +---+---+---+---+---+---+---+---+
        # Source: https://tools.ietf.org/html/rfc6282, Figure 3: LOWPAN_IPHC Encoding
        self.bytes += 1

      # 2. In-line IP Fields

      if sixlowpan.get_field_value('iphc_tf', raw=True) == '0':
        #                      1                   2                   3
        #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |ECN|   DSCP    |  rsv  |             Flow Label                |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # Source: https://tools.ietf.org/html/rfc6282, Figure 4: TF = 00: Traffic Class and Flow Label carried in-line
        self.bytes += 4
      elif sixlowpan.get_field_value('iphc_tf', raw=True) == '1':
        #                      1                   2
        #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |ECN|rsv|             Flow Label                |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # Source: https://tools.ietf.org/html/rfc6282, Figure 5: TF = 01: Flow Label carried in-line
        self.bytes += 3
      elif sixlowpan.get_field_value('iphc_tf', raw=True) == '10':
        #  0 1 2 3 4 5 6 7
        # +-+-+-+-+-+-+-+-+
        # |ECN|   DSCP    |
        # +-+-+-+-+-+-+-+-+
        # Source: https://tools.ietf.org/html/rfc6282, Figure 6: TF = 10: Traffic Class carried in-line
        self.bytes += 1

      if sixlowpan.get_field_value('iphc_hlim', raw=True) == '0':
        self.bytes += 1
      
      # Caution: We are not covering all cases here, only the ones observed in the capture.
      # For information on other cases, see https://tools.ietf.org/html/rfc6282, pages 7-10

      if sixlowpan.get_field_value('iphc_sac', raw=True) == '1' and sixlowpan.get_field_value('iphc_sam', raw=True) == '1':
        self.bytes += 8
      elif sixlowpan.get_field_value('iphc_sac', raw=True) == '1' and sixlowpan.get_field_value('iphc_sam', raw=True) == '3':
        self.bytes += 0
      elif sixlowpan.get_field_value('iphc_sac', raw=True) != None or sixlowpan.get_field_value('iphc_sam', raw=True) != None:
        print("WARNING: 6LOWPAN field 'iphc_sac' has unhandled value", sixlowpan.get_field_value('iphc_sac', raw=True))
        print("WARNING: 6LOWPAN field 'iphc_sam' has unhandled value", sixlowpan.get_field_value('iphc_sam', raw=True))

      if sixlowpan.get_field_value('iphc_m', raw=True) == '0' and sixlowpan.get_field_value('iphc_dac', raw=True) == '1' and sixlowpan.get_field_value('iphc_dam', raw=True) == '1':
        self.bytes += 8
      elif sixlowpan.get_field_value('iphc_m', raw=True) == '0' and sixlowpan.get_field_value('iphc_dac', raw=True) == '1' and sixlowpan.get_field_value('iphc_dam', raw=True) == '3':
        self.bytes += 0
      elif sixlowpan.get_field_value('iphc_m', raw=True) != None or sixlowpan.get_field_value('iphc_dac', raw=True) != None or sixlowpan.get_field_value('iphc_dam', raw=True) != None:
        print("WARNING: 6LOWPAN field 'iphc_m' has unhandled value", sixlowpan.get_field_value('iphc_m', raw=True))
        print("WARNING: 6LOWPAN field 'iphc_dac' has unhandled value", sixlowpan.get_field_value('iphc_dac', raw=True))
        print("WARNING: 6LOWPAN field 'iphc_dam' has unhandled value", sixlowpan.get_field_value('iphc_dam', raw=True))

      # 3. LOWPAN_NHC Encoding

      if sixlowpan.get_field_value('nhc_pattern') != None and sixlowpan.nhc_pattern.binary_value[0] & b'\xF0'[0] == 224: # 11100000
        #   0   1   2   3   4   5   6   7
        # +---+---+---+---+---+---+---+---+
        # | 1 | 1 | 1 | 0 |    EID    |NH |
        # +---+---+---+---+---+---+---+---+
        # Source: https://tools.ietf.org/html/rfc6282, Figure 13: IPv6 Extension Header Encoding
        self.bytes += 1

        if sixlowpan.get_field_value('nhc_ext_nh', raw=True) == '0':
          self.bytes += 1 # For "Next header" field

        if sixlowpan.get_field_value('nhc_ext_length', raw=True) != None:
          self.bytes += 1 # For "Header length" field
          self.bytes += int(sixlowpan.get_field_value('nhc_ext_length', raw=True))

    elif sixlowpan.pattern == "0x0000001c":
      # Fragment
      self.bytes += 5

    else:
      print("WARNING: 6LOWPAN field 'pattern' has unhandled value", sixlowpan.pattern)