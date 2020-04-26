<?php

/*!
 * siphash.php v1.0.2
 *
 * © 2020 Yuji Hase
 *
 * Released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

// --------------------------------------------------
// SipHash
// --------------------------------------------------

if (PHP_INT_SIZE >= 8) {
  class SipHash {
    static function hash($length, $data, $key, $raw_output = false) {

      assert(($length == 8 || $length == 16) && strlen($key) == 16);

      /* SipHash-2-4 */
      static $c_rounds = 2;
      static $d_rounds = 4;

      $k = unpack('P2', $key);
      $v0 = 0x736f6d6570736575 ^ $k[1];
      $v1 = 0x646f72616e646f6d ^ $k[2];
      $v2 = 0x6c7967656e657261 ^ $k[1];
      $v3 = 0x7465646279746573 ^ $k[2];

      if ($length == 16) {
        $v1 ^= 0xee;
      }

      $m = unpack('P*', $data."\0\0\0\0\0\0\0\0");
      $b = array_pop($m) | (strlen($data) << 56);

      foreach ($m as $a) {
        $v3 ^= $a;
        self::sipround($v0, $v1, $v2, $v3, $c_rounds);
        $v0 ^= $a;
      }

      $v3 ^= $b;
      self::sipround($v0, $v1, $v2, $v3, $c_rounds);
      $v0 ^= $b;

      $v2 ^= $length == 16 ? 0xee : 0xff;
      self::sipround($v0, $v1, $v2, $v3, $d_rounds);
      $output = pack('P', $v0 ^ $v1 ^ $v2 ^ $v3);

      if ($length == 16) {
        $v1 ^= 0xdd;
        self::sipround($v0, $v1, $v2, $v3, $d_rounds);
        $output .= pack('P', $v0 ^ $v1 ^ $v2 ^ $v3);
      }

      return $raw_output ? $output : bin2hex($output);
    }

    private static function sipround(&$v0, &$v1, &$v2, &$v3, $n) {
      for ($i = 0; $i < $n; $i++) {
        $c = ($v0 & 0xffffffff) + ($v1 & 0xffffffff);
        $v0 = ($c & 0xffffffff) | ((($v0 >> 32) + ($v1 >> 32) + ($c >> 32)) << 32);
        $v1 = ($v1 << 13) | (($v1 >> 51) & 0x1fff);
        $v1 ^= $v0;
        $v0 = ($v0 << 32) | (($v0 >> 32) & 0xffffffff);
        $c = ($v2 & 0xffffffff) + ($v3 & 0xffffffff);
        $v2 = ($c & 0xffffffff) | ((($v2 >> 32) + ($v3 >> 32) + ($c >> 32)) << 32);
        $v3 = ($v3 << 16) | (($v3 >> 48) & 0xffff);
        $v3 ^= $v2;
        $c = ($v0 & 0xffffffff) + ($v3 & 0xffffffff);
        $v0 = ($c & 0xffffffff) | ((($v0 >> 32) + ($v3 >> 32) + ($c >> 32)) << 32);
        $v3 = ($v3 << 21) | (($v3 >> 43) & 0x1fffff);
        $v3 ^= $v0;
        $c = ($v2 & 0xffffffff) + ($v1 & 0xffffffff);
        $v2 = ($c & 0xffffffff) | ((($v2 >> 32) + ($v1 >> 32) + ($c >> 32)) << 32);
        $v1 = ($v1 << 17) | (($v1 >> 47) & 0x1ffff);
        $v1 ^= $v2;
        $v2 = ($v2 << 32) | (($v2 >> 32) & 0xffffffff);
      }
    }
  }
} else {
  class SipHash {
    static function hash($length, $data, $key, $raw_output = false) {

      assert(($length == 8 || $length == 16) && strlen($key) == 16);

      /* SipHash-2-4 */
      static $c_rounds = 2;
      static $d_rounds = 4;

      $v0 = self::str8_to_u64("\x75\x65\x73\x70\x65\x6d\x6f\x73");
      $v1 = self::str8_to_u64("\x6d\x6f\x64\x6e\x61\x72\x6f\x64");
      $v2 = self::str8_to_u64("\x61\x72\x65\x6e\x65\x67\x79\x6c");
      $v3 = self::str8_to_u64("\x73\x65\x74\x79\x62\x64\x65\x74");

      $k0 = self::str8_to_u64(substr($key, 0, 8));
      $k1 = self::str8_to_u64(substr($key, 8, 8));
      self::xor_asgmt($v0, $k0);
      self::xor_asgmt($v1, $k1);
      self::xor_asgmt($v2, $k0);
      self::xor_asgmt($v3, $k1);

      if ($length == 16) {
        self::xor_asgmt($v1, self::u64(0xee));
      }

      $size = strlen($data);
      $end = $size & ~7;

      for ($ptr = 0; $ptr != $end; $ptr += 8) {
        $m = self::str8_to_u64(substr($data, $ptr, 8));
        self::xor_asgmt($v3, $m);
        self::sipround($v0, $v1, $v2, $v3, $c_rounds);
        self::xor_asgmt($v0, $m);
      }

      $m = self::str_to_u64(substr($data, $end));
      self::or_asgmt($m, self::shl56(self::u64($size)));
      self::xor_asgmt($v3, $m);
      self::sipround($v0, $v1, $v2, $v3, $c_rounds);
      self::xor_asgmt($v0, $m);

      self::xor_asgmt($v2, self::u64($length == 16 ? 0xee : 0xff));
      self::sipround($v0, $v1, $v2, $v3, $d_rounds);
      $output = self::output($v0, $v1, $v2, $v3);

      if ($length == 16) {
        self::xor_asgmt($v1, self::u64(0xdd));
        self::sipround($v0, $v1, $v2, $v3, $d_rounds);
        $output .= self::output($v0, $v1, $v2, $v3);
      }

      return $raw_output ? $output : bin2hex($output);
    }

    // 8 bytes to 64 bits
    private static function str8_to_u64($data) {
      return array_merge(unpack('v*', $data));
    }

    // N bytes to 64 bits
    private static function str_to_u64($data) {
      $p = array_merge(unpack('C*', $data));
      $a = self::u64(0);
      for ($j = 0; $j < count($a); $j++) {
        for ($i = 0; $i < min(count($p) - 2 * $j, 2); $i++) {
          $a[$j] |= $p[$i + 2 * $j] << ($i * 8);
        }
      }
      return $a;
    }

    // output 8 bytes
    private static function output($v0, $v1, $v2, $v3) {
      return pack('v*',
        $v0[0] ^ $v1[0] ^ $v2[0] ^ $v3[0],
        $v0[1] ^ $v1[1] ^ $v2[1] ^ $v3[1],
        $v0[2] ^ $v1[2] ^ $v2[2] ^ $v3[2],
        $v0[3] ^ $v1[3] ^ $v2[3] ^ $v3[3]);
    }

    private static function sipround(&$v0, &$v1, &$v2, &$v3, $n) {
      for ($i = 0; $i < $n; $i++) {
        self::add_asgmt($v0, $v1);
        self::rotl0_asgmt($v1, 13);
        self::xor_asgmt($v1, $v0);
        self::rotl32_asgmt($v0);
        self::add_asgmt($v2, $v3);
        self::rotl16_asgmt($v3);
        self::xor_asgmt($v3, $v2);
        self::add_asgmt($v0, $v3);
        self::rotl16_asgmt($v3, 5);
        self::xor_asgmt($v3, $v0);
        self::add_asgmt($v2, $v1);
        self::rotl16_asgmt($v1, 1);
        self::xor_asgmt($v1, $v2);
        self::rotl32_asgmt($v2);
      }
    }

    // Create 64 bits data
    private static function u64($a) {
      return array($a & 0xffff, ($a >> 16) & 0xffff, 0, 0);
    }

    // Left shift by 56 bits
    private static function shl56($a) {
      return array(0, 0, 0, ($a[0] << 8) & 0xffff);
    }

    private static function add_asgmt(&$a, $b) {
      $c0 = $a[0] + $b[0];
      $c1 = $a[1] + $b[1] + ($c0 >> 16);
      $c2 = $a[2] + $b[2] + ($c1 >> 16);
      $c3 = $a[3] + $b[3] + ($c2 >> 16);
      $a = array($c0 & 0xffff, $c1 & 0xffff, $c2 & 0xffff, $c3 & 0xffff);
    }

    private static function or_asgmt(&$a, $b) {
      $a[0] |= $b[0];
      $a[1] |= $b[1];
      $a[2] |= $b[2];
      $a[3] |= $b[3];
    }

    private static function xor_asgmt(&$a, $b) {
      $a[0] ^= $b[0];
      $a[1] ^= $b[1];
      $a[2] ^= $b[2];
      $a[3] ^= $b[3];
    }

    // ------------------------------
    // Rotl - Circular left shift
    // ------------------------------

    // Rotl by 0-15 bits
    private static function rotl0_asgmt(&$a, $n = 0) {
      $m = 16 - $n;
      $a = array(
        (($a[0] << $n) & 0xffff) | ($a[3] >> $m),
        (($a[1] << $n) & 0xffff) | ($a[0] >> $m),
        (($a[2] << $n) & 0xffff) | ($a[1] >> $m),
        (($a[3] << $n) & 0xffff) | ($a[2] >> $m),
      );
    }

    // Rotl by 16-31 bits
    private static function rotl16_asgmt(&$a, $n = 0) {
      $m = 16 - $n;
      $a = array(
        (($a[3] << $n) & 0xffff) | ($a[2] >> $m),
        (($a[0] << $n) & 0xffff) | ($a[3] >> $m),
        (($a[1] << $n) & 0xffff) | ($a[0] >> $m),
        (($a[2] << $n) & 0xffff) | ($a[1] >> $m),
      );
    }

    // Rotl by 32 bits
    private static function rotl32_asgmt(&$a) {
      $a = array($a[2], $a[3], $a[0], $a[1]);
    }
  }
}

?>