<?php

/*!
 * siphash.php v1
 *
 * © 2020 Yuji Hase
 *
 * Released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

if (PHP_INT_SIZE >= 8) {

  // ------------------------------------------------------------
  // Core routines for environment calculatable up to 0xffffffff
  // ------------------------------------------------------------

  class _SHCore {

    // 8 bytes to 64 bits
    static function str8_to_u64($data) {
      return array_merge(unpack('V*', $data));
    }

    // N bytes to 64 bits
    static function str_to_u64($data) {
      $p = array_merge(unpack('C*', $data));
      $a = self::u64(0);
      for ($j = 0; $j < count($a); $j++) {
        for ($i = 0; $i < min(count($p) - 4 * $j, 4); $i++) {
          $a[$j] |= $p[$i + 4 * $j] << ($i * 8);
        }
      }
      return $a;
    }

    // output 8 bytes
    static function output($v0, $v1, $v2, $v3) {
      return pack('V*',
        $v0[0] ^ $v1[0] ^ $v2[0] ^ $v3[0],
        $v0[1] ^ $v1[1] ^ $v2[1] ^ $v3[1]);
    }

    static function sipround(&$v0, &$v1, &$v2, &$v3, $n) {
      for ($i = 0; $i < $n; $i++) {
        self::add_asgmt($v0, $v1);
        self::rotl0_asgmt($v1, 13);
        self::xor_asgmt($v1, $v0);
        self::rotl32_asgmt($v0);
        self::add_asgmt($v2, $v3);
        self::rotl0_asgmt($v3, 16);
        self::xor_asgmt($v3, $v2);
        self::add_asgmt($v0, $v3);
        self::rotl0_asgmt($v3, 21);
        self::xor_asgmt($v3, $v0);
        self::add_asgmt($v2, $v1);
        self::rotl0_asgmt($v1, 17);
        self::xor_asgmt($v1, $v2);
        self::rotl32_asgmt($v2);
      }
    }

    // Create 64 bits data
    static function u64($a) {
      return array($a & 0xffffffff, ($a >> 32) & 0xffffffff);
    }

    // Left shift by 56 bits
    static function shl56($a) {
      return array(0, ($a[0] << 24) & 0xffffffff);
    }

    private static function add_asgmt(&$a, $b) {
      $c0 = $a[0] + $b[0];
      $c1 = $a[1] + $b[1] + ($c0 >> 32);
      $a = array($c0 & 0xffffffff, $c1 & 0xffffffff);
    }

    static function or_asgmt(&$a, $b) {
      $a[0] |= $b[0];
      $a[1] |= $b[1];
    }

    static function xor_asgmt(&$a, $b) {
      $a[0] ^= $b[0];
      $a[1] ^= $b[1];
    }

    // ------------------------------
    // Rotl - Circular left shift
    // ------------------------------

    // Rotl by 0-31 bits
    private static function rotl0_asgmt(&$a, $n) {
      $m = 32 - $n;
      $a = array(
        (($a[0] << $n) & 0xffffffff) | ($a[1] >> $m),
        (($a[1] << $n) & 0xffffffff) | ($a[0] >> $m),
      );
    }

    // Rotl by 32 bits
    private static function rotl32_asgmt(&$a) {
      $a = array($a[1], $a[0]);
    }
  }
} else {

  // ------------------------------------------------------------
  // Core routines for environment calculatable up to 0xffff
  // ------------------------------------------------------------

  class _SHCore {

    // 8 bytes to 64 bits
    static function str8_to_u64($data) {
      return array_merge(unpack('v*', $data));
    }

    // N bytes to 64 bits
    static function str_to_u64($data) {
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
    static function output($v0, $v1, $v2, $v3) {
      return pack('v*',
        $v0[0] ^ $v1[0] ^ $v2[0] ^ $v3[0],
        $v0[1] ^ $v1[1] ^ $v2[1] ^ $v3[1],
        $v0[2] ^ $v1[2] ^ $v2[2] ^ $v3[2],
        $v0[3] ^ $v1[3] ^ $v2[3] ^ $v3[3]);
    }

    static function sipround(&$v0, &$v1, &$v2, &$v3, $n) {
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
    static function u64($a) {
      return array($a & 0xffff, ($a >> 16) & 0xffff, 0, 0);
    }

    // Left shift by 56 bits
    static function shl56($a) {
      return array(0, 0, 0, ($a[0] << 8) & 0xffff);
    }

    private static function add_asgmt(&$a, $b) {
      $c0 = $a[0] + $b[0];
      $c1 = $a[1] + $b[1] + ($c0 >> 16);
      $c2 = $a[2] + $b[2] + ($c1 >> 16);
      $c3 = $a[3] + $b[3] + ($c2 >> 16);
      $a = array($c0 & 0xffff, $c1 & 0xffff, $c2 & 0xffff, $c3 & 0xffff);
    }

    static function or_asgmt(&$a, $b) {
      $a[0] |= $b[0];
      $a[1] |= $b[1];
      $a[2] |= $b[2];
      $a[3] |= $b[3];
    }

    static function xor_asgmt(&$a, $b) {
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

// --------------------------------------------------
// SipHash
// --------------------------------------------------

class SipHash {
  static function hash($length, $data, $key, $raw_output = false) {

    assert(($length == 8 || $length == 16) && strlen($key) == 16);

    /* SipHash-2-4 */
    static $c_rounds = 2;
    static $d_rounds = 4;

    $v0 = _SHCore::str8_to_u64("\x75\x65\x73\x70\x65\x6d\x6f\x73");
    $v1 = _SHCore::str8_to_u64("\x6d\x6f\x64\x6e\x61\x72\x6f\x64");
    $v2 = _SHCore::str8_to_u64("\x61\x72\x65\x6e\x65\x67\x79\x6c");
    $v3 = _SHCore::str8_to_u64("\x73\x65\x74\x79\x62\x64\x65\x74");

    $k0 = _SHCore::str8_to_u64(substr($key, 0, 8));
    $k1 = _SHCore::str8_to_u64(substr($key, 8, 8));
    _SHCore::xor_asgmt($v0, $k0);
    _SHCore::xor_asgmt($v1, $k1);
    _SHCore::xor_asgmt($v2, $k0);
    _SHCore::xor_asgmt($v3, $k1);

    if ($length == 16) {
      _SHCore::xor_asgmt($v1, _SHCore::u64(0xee));
    }

    $size = strlen($data);
    $end = $size & ~7;

    for ($ptr = 0; $ptr != $end; $ptr += 8) {
      $m = _SHCore::str8_to_u64(substr($data, $ptr, 8));
      _SHCore::xor_asgmt($v3, $m);
      _SHCore::sipround($v0, $v1, $v2, $v3, $c_rounds);
      _SHCore::xor_asgmt($v0, $m);
    }

    $m = _SHCore::str_to_u64(substr($data, $end));
    _SHCore::or_asgmt($m, _SHCore::shl56(_SHCore::u64($size)));
    _SHCore::xor_asgmt($v3, $m);
    _SHCore::sipround($v0, $v1, $v2, $v3, $c_rounds);
    _SHCore::xor_asgmt($v0, $m);

    _SHCore::xor_asgmt($v2, _SHCore::u64($length == 16 ? 0xee : 0xff));
    _SHCore::sipround($v0, $v1, $v2, $v3, $d_rounds);
    $output = _SHCore::output($v0, $v1, $v2, $v3);

    if ($length == 16) {
      _SHCore::xor_asgmt($v1, _SHCore::u64(0xdd));
      _SHCore::sipround($v0, $v1, $v2, $v3, $d_rounds);
      $output .= _SHCore::output($v0, $v1, $v2, $v3);
    }

    return $raw_output ? $output : bin2hex($output);
  }
}

?>
