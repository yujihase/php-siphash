<?php

require_once('siphash.php');

set_time_limit(0);

$key = "";
for ($i = 0; $i < 16; $i++) {
  $key .= pack("C", $i + $i * 16);
}

$in = "";
for ($i = 0; $i < 4096; $i++) {
  $in .= pack("C", $i);
}

$t = microtime(true);
for ($i = 0; $i <= strlen($in); $i++) {
  $data = substr($in, 0, $i);
  $hash = SipHash::hash(16, $data, $key, true);
  echo bin2hex($hash), "\n";
}
for ($i = 0; $i <= strlen($in); $i++) {
  $data = substr($in, 0, $i);
  $hash = SipHash::hash(8, $data, $key, true);
  echo bin2hex($hash), "\n";
}
printf("elapsed time: %f secs.\n", microtime(true) - $t);

?>