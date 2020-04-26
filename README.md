# php-siphash

SipHash library for pure PHP 5.0.5+.

It is implemented with portability and compatibility first, not speed.

You need no more extensions, modules, frameworks.

Based on [Jean-Philippe Aumasson's SipHash Implementation](https://github.com/veorq/SipHash).

## How to use

1. Import `siphash.php`.
```
require_once('siphash.php');
```

2. Call hash function.
```
$key = "\x01\x23\x45\x67\x89\xab\xcd\xef\x00\xff\x00\xff\x00\xff\x00\xff";
$hash = SipHash::hash(16, "hello, world\n", $key);
echo "{$hash}\n";
```

3. Displayed.
```
88e71294c29466b29c9d59b11feba87d
```

## Function Reference

```
function SipHash::hash(int $length, string $data, string $key, bool $raw_output = false)
```

* `$length` ... A length of hash. If you need 64-bit hash, `$length = 8`. If 128-bit, `$length = 16`.
* `$data` ... Data that will be hashed.
* `$key` ... Hash key. This must be 16 bytes string.
* `$raw_output` ... If this is true, the function returns binary data which length is `$length`. If false, hexized string. Default is false.
