<?php

/*!
 * siphash.php v1.0.4
 *
 * © 2020 Yuji Hase
 *
 * Released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

// --------------------------------------------------
// SipHash
// --------------------------------------------------

if (!defined('PHP_VERSION_ID')) {
  $version = explode('.', PHP_VERSION);
  define('PHP_VERSION_ID', ($version[0] * 10000 + $version[1] * 100 + $version[2]));
}

if (PHP_INT_SIZE == 8 && PHP_VERSION_ID >= 50603) {
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

      // 64-bits int is expressed an array of 24-bits, 24-bits, 16-bits.

      $v0 = self::str8_to_u64("\x75\x65\x73\x70\x65\x6d\x6f\x73");
      $v1 = self::str8_to_u64("\x6d\x6f\x64\x6e\x61\x72\x6f\x64");
      $v2 = self::str8_to_u64("\x61\x72\x65\x6e\x65\x67\x79\x6c");
      $v3 = self::str8_to_u64("\x73\x65\x74\x79\x62\x64\x65\x74");

      $k0 = self::str8_to_u64(substr($key, 0, 8));
      $k1 = self::str8_to_u64(substr($key, 8, 8));
      $v0[0] ^= $k0[0]; $v0[1] ^= $k0[1]; $v0[2] ^= $k0[2];
      $v1[0] ^= $k1[0]; $v1[1] ^= $k1[1]; $v1[2] ^= $k1[2];
      $v2[0] ^= $k0[0]; $v2[1] ^= $k0[1]; $v2[2] ^= $k0[2];
      $v3[0] ^= $k1[0]; $v3[1] ^= $k1[1]; $v3[2] ^= $k1[2];

      if ($length == 16) {
        $v1[0] ^= 0xee;
      }

      $size = strlen($data);
      $end = $size & ~7;

      for ($ptr = 0; $ptr != $end; $ptr += 8) {
        $m = self::str8_to_u64(substr($data, $ptr, 8));
        $v3[0] ^= $m[0]; $v3[1] ^= $m[1]; $v3[2] ^= $m[2];
        self::sipround($v0, $v1, $v2, $v3, $c_rounds);
        $v0[0] ^= $m[0]; $v0[1] ^= $m[1]; $v0[2] ^= $m[2];
      }

      $m = self::str_to_u64(substr($data, $end));
      $m[2] |= ($size & 0xff) << 8;
      $v3[0] ^= $m[0]; $v3[1] ^= $m[1]; $v3[2] ^= $m[2];
      self::sipround($v0, $v1, $v2, $v3, $c_rounds);
      $v0[0] ^= $m[0]; $v0[1] ^= $m[1]; $v0[2] ^= $m[2];

      $v2[0] ^= $length == 16 ? 0xee : 0xff;
      self::sipround($v0, $v1, $v2, $v3, $d_rounds);
      $output = self::output($v0, $v1, $v2, $v3);

      if ($length == 16) {
        $v1[0] ^= 0xdd;
        self::sipround($v0, $v1, $v2, $v3, $d_rounds);
        $output .= self::output($v0, $v1, $v2, $v3);
      }

      return $raw_output ? $output : bin2hex($output);
    }

    // 8 bytes to 64 bits
    private static function str8_to_u64($data) {
      $a = unpack('V2', $data);
      return array(
        $a[1] & 0xffffff,
        (($a[1] >> 24) & 0xff) | (($a[2] & 0xffff) << 8),
        ($a[2] >> 16) & 0xffff,
      );
    }

    // N bytes to 64 bits
    private static function str_to_u64($data) {
      $p = array_merge(unpack('C*', $data));
      $a = array(0, 0, 0);
      for ($j = 0; $j < count($a); $j++) {
        for ($i = 0; $i < min(count($p) - 3 * $j, 3); $i++) {
          $a[$j] |= $p[$i + 3 * $j] << ($i * 8);
        }
      }
      return $a;
    }

    // output 8 bytes
    private static function output($v0, $v1, $v2, $v3) {
      $a0 = $v0[0] ^ $v1[0] ^ $v2[0] ^ $v3[0];
      $a1 = $v0[1] ^ $v1[1] ^ $v2[1] ^ $v3[1];
      $a2 = $v0[2] ^ $v1[2] ^ $v2[2] ^ $v3[2];
      return pack('V2', $a0 | ($a1 << 24), (($a1 >> 8) & 0xffff) | ($a2 << 16));
    }

    private static function sipround(&$v0, &$v1, &$v2, &$v3, $n) {
      for ($i = 0; $i < $n; $i++) {
        /* v0 += v1 */ {
          $c0 = $v0[0] + $v1[0];
          $c1 = $v0[1] + $v1[1] + ($c0 >> 24);
          $c2 = $v0[2] + $v1[2] + ($c1 >> 24);
          $v0 = array($c0 & 0xffffff, $c1 & 0xffffff, $c2 & 0xffff);
        }
        /* Rotl by 13 bits */ $v1 = array(
          ($v1[2] >> 3) | (($v1[0] & 0x7ff) << 13),
          ($v1[0] >> 11) | (($v1[1] & 0x7ff) << 13),
          ($v1[1] >> 11) | (($v1[2] & 0x7) << 13),
        );
        /* v1 ^= v0 */ $v1[0] ^= $v0[0]; $v1[1] ^= $v0[1]; $v1[2] ^= $v0[2];
        /* Rotl by 32 bits */ $v0 = array(
          ($v0[1] >> 8) | (($v0[2] & 0xff) << 16),
          ($v0[2] >> 8) | (($v0[0] & 0xffff) << 8),
          ($v0[0] >> 16) | (($v0[1] & 0xff) << 8),
        );
        /* v2 += v3 */ {
          $c0 = $v2[0] + $v3[0];
          $c1 = $v2[1] + $v3[1] + ($c0 >> 24);
          $c2 = $v2[2] + $v3[2] + ($c1 >> 24);
          $v2 = array($c0 & 0xffffff, $c1 & 0xffffff, $c2 & 0xffff);
        }
        /* Rotl by 16 bits */ $v3 = array(
          $v3[2] | (($v3[0] & 0xff) << 16),
          ($v3[0] >> 8) | (($v3[1] & 0xff) << 16),
          $v3[1] >> 8,
        );
        /* v3 ^= v2 */ $v3[0] ^= $v2[0]; $v3[1] ^= $v2[1]; $v3[2] ^= $v2[2];
        /* v0 += v3 */ {
          $c0 = $v0[0] + $v3[0];
          $c1 = $v0[1] + $v3[1] + ($c0 >> 24);
          $c2 = $v0[2] + $v3[2] + ($c1 >> 24);
          $v0 = array($c0 & 0xffffff, $c1 & 0xffffff, $c2 & 0xffff);
        }
        /* Rotl by 21 bits */ $v3 = array(
          ($v3[1] >> 19) | ($v3[2] << 5) | (($v3[0] & 0x7) << 21),
          ($v3[0] >> 3) | (($v3[1] & 0x7) << 21),
          ($v3[1] >> 3) & 0xffff,
        );
        /* v3 ^= v0 */ $v3[0] ^= $v0[0]; $v3[1] ^= $v0[1]; $v3[2] ^= $v0[2];
        /* v2 += v1 */ {
          $c0 = $v2[0] + $v1[0];
          $c1 = $v2[1] + $v1[1] + ($c0 >> 24);
          $c2 = $v2[2] + $v1[2] + ($c1 >> 24);
          $v2 = array($c0 & 0xffffff, $c1 & 0xffffff, $c2 & 0xffff);
        }
        /* Rotl by 17 bits */ $v1 = array(
          ($v1[1] >> 23) | ($v1[2] << 1) | (($v1[0] & 0x7f) << 17),
          ($v1[0] >> 7) | (($v1[1] & 0x7f) << 17),
          ($v1[1] >> 7) & 0xffff,
        );
        /* v1 ^= v2 */ $v1[0] ^= $v2[0]; $v1[1] ^= $v2[1]; $v1[2] ^= $v2[2];
        /* Rotl by 32 bits */ $v2 = array(
          ($v2[1] >> 8) | (($v2[2] & 0xff) << 16),
          ($v2[2] >> 8) | (($v2[0] & 0xffff) << 8),
          ($v2[0] >> 16) | (($v2[1] & 0xff) << 8),
        );
      }
    }
  }
}

?>