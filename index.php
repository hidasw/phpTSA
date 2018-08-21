<?php
// Script writted By Hida <hidactive@gmail.com>
// Last change at 14:30 Sore Senin 23 Maret 2009 req not based of content-type header,
// but based on req structure
// Last script update 20:56 Sore 23/03/2009
// Last script update 10:46 Esuk 09/07/2009
// Last script update 15:03 Sore 29/08/2009
// Last script update 03:32 Esuk 03/09/2009
// Last script update 7:24 PM 8/20/2018

error_reporting(0);
include 'funct_log.php';
include 'config.php';
$cfg = tsa_config('tsa.cfg');
if(!is_array($cfg)) {
  tsalog("Configuration file error: $cfg", 'e');
  header("HTTP/1.0 500 Internal Server Error");
  exit;
}

//$req = $HTTP_RAW_POST_DATA;
$req = file_get_contents("php://input");
//$req = file_get_contents("lastreq0.der");

if(empty($req) || strlen($req) < 39) {
  tsalog("malformedRequest: request length (".strlen($req).") < 39 char. User agent: {$_SERVER["HTTP_USER_AGENT"]}", 'i');
  header("HTTP/1.0 403 Forbidden");
  exit;
}

include 'tsa_function.php';
include 'genOid.php';
if(!defined('OBJ_'.TSA_HASHALGORITHM)) {
  tsalog("Configuration file error: unknown algorithm: ".TSA_HASHALGORITHM, 'e');
  header("HTTP/1.0 500 Internal Server Error");
  exit;
}

include 'dbconnect.php';
$MySQL = dbconnect();
if(is_object($MySQL)) {
  //$Q_selectSigner = mysqli_query($MySQL, "select min(`order`) from `signer` where `use` = '1'");
  $Q_selectSigner = mysqli_query($MySQL, "select `id` from `signer` where `use` = '1'");

  if(!$Q_selectSigner || mysqli_num_rows($Q_selectSigner) < 1) {
    tsalog("Can't select signer\nRow result = ".mysqli_num_rows($Q_selectSigner)."\nMySQL say ".mysqli_error($MySQL), 'e');
    header("HTTP/1.0 500 Internal Server Error");
    exit;
  }
  mysqli_free_result($Q_selectSigner);
  $Q_selectSigner = mysqli_query($MySQL, "select max(`id`) from `signer` where `use` = '1'");
  $R_selectSigner = mysqli_fetch_array($Q_selectSigner);

  mysqli_free_result($Q_selectSigner);
  $Q_tsaSigner = mysqli_query($MySQL, "select `cert`,`pkey`,`pwd` from `signer` where `id` = '{$R_selectSigner[0]}'");
  $Q_tsaExtraCerts = mysqli_query($MySQL, "select `cert` from `extracerts` where `use` = 1 order by `order`");
  $Q_tsaCrls = mysqli_query($MySQL, "select * from `".TSA_TABLECRLS."` where `use`='1' order by `order`");
  $Q_tsaLastSerial = mysqli_query($MySQL, "select max(`serialNumber`) from `".TSA_TABLELOGS."`");
  if(!$Q_tsaSigner || !$Q_tsaExtraCerts || !$Q_tsaCrls || !$Q_tsaLastSerial) {
    tsalog("Database query Error\nMySQL Say ".mysqli_error(), 'e');
    header("HTTP/1.0 500 Internal Server Error");
    exit;
  }
  $TSA['signer'] = mysqli_fetch_assoc($Q_tsaSigner);
  while($TSAextracerts = mysqli_fetch_assoc($Q_tsaExtraCerts)) {
    $TSA['extracerts'][] = $TSAextracerts['cert'];
  }
  while($TSAcrls = mysqli_fetch_assoc($Q_tsaCrls)) {
    $TSA['crls'][] = $TSAcrls['crl'];
  }
  //echo "<pre>";
  //print_r($TSA);
  $TSAserialarr = mysqli_fetch_array($Q_tsaLastSerial);
  $TSA['serial'] = $TSAserialarr[0];
  
  mysqli_free_result($Q_tsaSigner);
  mysqli_free_result($Q_tsaExtraCerts);
  mysqli_free_result($Q_tsaCrls);
  mysqli_free_result($Q_tsaLastSerial);
} else {
  tsalog("Database connection Error\n: $MySQL", 'e');
  header("HTTP/1.0 500 Internal Server Error");
  exit;
}

if($PARSED_REQ = tsa_parsereq($req, $use_tsa)) {
  $h = fopen('lastReq.der','w');
  fwrite($h, $req);
  fclose($h);
  if($use_tsa == 1) {
    include 'tsa_0.php';
  }
  if($use_tsa == 2) {
    include 'tsa_1.php';
  }
} else {
  tsalog("malformedRequest: Can't parse request", 'i');
  header("HTTP/1.0 403 Forbidden");
}

if($MySQL) {
  mysqli_close($MySQL);
}
?>