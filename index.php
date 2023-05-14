<?php
// Script writted By Hida <hidactive@gmail.com>
// Last change at 14:30 Sore Senin 23 Maret 2009 req not based of content-type header,
// but based on req structure
// Last script update 20:56 Sore 23/03/2009
// Last script update 10:46 Esuk 09/07/2009
// Last script update 15:03 Sore 29/08/2009
// Last script update 03:32 Esuk 03/09/2009
// Last script update 7:24 PM 8/20/2018
// Last script update Minggu 14 Mei 2023 21:05:22 Sore
// 
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
// testing purpose
// $req = file_get_contents("req.signtool.der");
// $req = file_get_contents("req.signtoolnew.der");
// $req = file_get_contents("req.bak.der");

// $h = fopen('req.der','w');
// fwrite($h, $req);
// fclose($h);

// $header = print_r(apache_request_headers(),1);
// $h = fopen('reqheader.txt','w');
// fwrite($h, $header);
// fclose($h);



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

  $certsdir=realpath('certs');
  $extracertsdir=realpath('certs/extracerts');
  $crlsdir=realpath('certs/crls');
  $signer = file_get_contents($certsdir.'/signer.pem');
  if(openssl_x509_read($signer) && openssl_pkey_get_private($signer)) {
	$TSA['signer'] = $signer;
  }

  if ($handle = opendir($extracertsdir)) {
      while (false !== ($entry = readdir($handle))) {
          $file=$extracertsdir."/".$entry;
		  if (is_file($file)) {
              $filect = file_get_contents($file);
              if(openssl_x509_read($filect)) {
				 $TSA['extracerts'][] = $filect;
			  }
          }
      }
      closedir($handle);
  }

  if ($handle = opendir($crlsdir)) {
      while (false !== ($entry = readdir($handle))) {
          $file=$crlsdir."/".$entry;
		  if (is_file($file)) {
              $filect = file_get_contents($file);
				 $TSA['crls'][] = $filect;
          }
      }
      closedir($handle);
  }
  
  // echo "<pre>";
  // print_r($TSA);
  $TSA['serial'] = file_get_contents('serial.txt');
  
// echo file_get_contents('openssl_r.txt');

if($PARSED_REQ = tsa_parsereq($req, $use_tsa)) {
	// print_r($PARSED_REQ);
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
?>