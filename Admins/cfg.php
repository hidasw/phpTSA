<?php

include '../config.php';
include '../dbconnect.php';
$tsaConfig = tsa_config('../tsa.cfg');
if(!is_array($tsaConfig)) {
  echo "ERROR: $tsaConfig";
  exit;
}
$db = dbconnect();
$cfg = false;
foreach($tsaConfig as $tsaConfigSectionK=>$tsaConfigSectionV) {
  if($tsaConfigSectionK == 'database') {
    $cfg .= "[database]\n";
    foreach(array_reverse($tsaConfigSectionV) as $k=>$v) {
      if($k != 'position') {
        $cfg .=  "$k = {$_GET[$k]}\n";
      }
    }
  }
  if($tsaConfigSectionK == 'common') {
    $cfg .= "\n[common]\n";
    $cfg .= "#md2 md4 md5 sha1 sha256 sha384 sha512 ripemd160 \n\n";
    foreach(array_reverse($tsaConfigSectionV) as $k=>$v) {
      if($k != 'position') {
        $cfg .=  "$k = {$_GET[$k]}\n";
      }
    }
  }
}


$h = fopen("../tsa.cfg", "w");
fwrite($h, $cfg);
fclose($h);

?>