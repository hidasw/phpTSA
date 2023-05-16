<?php
// ASN.1 Parser start 21:31 Sore Kamis 26 Maret 2009
// ASN.1 Parser at 22:10 Sore Kamis 26 Maret 2009 Telah jadi utk standar asn.1
// 
// 06:40 Esuk Jumat 27 Maret 2009 ASN.1 Parser kesulitan dlm memecahkan explicit > 9

// 11:18 Esuk Jumat 27 Maret 2009 parse explicit:xx mulai dipecahkan. kemungkinan tlh jadi
// 17:51 Sore Jumat 27 Maret 2009 memecahkan explicit sampai 2097151 (65536 * 32) kurang 1

// 20:04 Sore Jumat 27 Maret 2009 ASN.1 Parser tlh jadi. Congratulation....
function asn1_first($hex) {
  $asn1_Id = substr($hex, 0, 2);
  $header = substr($hex, 2, 2);
  if($asn1_Id == 'bf') {
    if(hexdec($header) > 128) {
      $headerLength = hexdec(substr($hex, 6, 2));
      $reduced = 8; // the string reduced by id & headerLength
      $expNum = (128*(hexdec($header)-128))+hexdec(substr($hex, 4, 2));
      $header2 = substr($hex, 4, 2);
      if(hexdec($header2) >= 128) {
        $headerLength = hexdec(substr($hex, 8, 2));
        $reduced = 10;
        $expNum = (16384*(hexdec($header)-128))+(128*(hexdec($header2)-128))+hexdec(substr($hex, 6, 2));
      }
    } else {
      $headerLength = hexdec(substr($hex, 4, 2));
      $reduced = 6;
      $expNum = hexdec(substr($hex, 2, 2));
    }
    $asn1_Id = "EXP:"."$expNum";
  } else {
    if($header == '83') {
      $headerLength = hexdec(substr($hex, 4, 6));
      $reduced = 10;
    } elseif ($header == '82') {
      $headerLength = hexdec(substr($hex, 4, 4));
      $reduced = 8;
    } elseif ($header == '81') {
      $headerLength = hexdec(substr($hex, 4, 2));
      $reduced = 6;
    } else {
      $headerLength = hexdec(substr($hex, 2, 2));
      $reduced = 4;
    }
  }
  $str_remains = substr($hex, $reduced+($headerLength*2));
  $content = substr($hex, $reduced, $headerLength*2);
  $return['res'] = array($asn1_Id, $content); // array 0=>iD(sequence be 30, integer be 02, etc) 1=>contents of id
  $return['rem'] = $str_remains; // the remain string returned
  if($str_remains == '' && $content == '') { // if remains string was empty & contents also empty, function return FALSE
    $return = false;
  }
  return $return;
}

function asn1parse($hex) {
  while(asn1_first($hex) != false) { // while asn1_first() still return string
    $r = asn1_first($hex);
    $return[] = array($r['res'][0],$r['res'][1]);
    $hex = $r['rem']; // $hex now be result of asn1_first()
  }
  return $return;
}
?>
<?php
// at 23:44 Sore Rabu 08 Juli 2009

//include 'asn1_parser.php';
//include 'asn1_function.php';

define ("OBJ_null", "0500");
define ('OBJ_md2', '06082A864886F70D0202');
define ('OBJ_md4', '06082A864886F70D0204');
define ("OBJ_md5", "06082A864886F70D0205");
define ("OBJ_sha1", "06052B0E03021A");
define ("OBJ_sha256", "0609608648016503040201");
define ('OBJ_sha224', '0609608648016503040204');
define ("OBJ_sha384", "0609608648016503040202");
define ("OBJ_sha512", "0609608648016503040203");
define ("OBJ_ripemd160", "06052B24030201");
define ("OBJ_rsaEncryption", "06092A864886F70D010101");

define("OBJ_pkcs7_signed", "06092A864886F70D010702");
define("OBJ_id_smime_ct_TSTInfo", "060B2A864886F70D0109100104");
define("OBJ_pkcs9_signingTime", "06092A864886F70D010905");
define("OBJ_pkcs9_messageDigest", "06092A864886F70D010904");
define("OBJ_pkcs9_contentType", "06092A864886F70D010903");
define("OBJ_id_smime_aa_securityLabel", "060B2A864886F70D0109100202");
define("OBJ_id_smime_aa_signingCertificate", "060B2A864886F70D010910020C");
define('OBJ_pkcs7_data', '06092A864886F70D010701');

function tsa_parsereqapl($base64req) {
  $binreq = base64_decode($base64req);
  $hex = bin2hex($binreq);
  $p = asn1parse($hex);
  if(substr($p[0][1], 0, 2) != '06' || $p[0][0] != '30') {
    return false;
  }
  $timestampRequest = asn1parse($p[0][1]);
  $tsr = reset($timestampRequest);
  if($tsr[0] == '06') {
    $tsReq['policy'] = $tsr[1];
    $tsr = next($timestampRequest);
  } else {
    return false;
  }
  if($tsr[0] == '30') {
    $p = asn1parse($tsr[1]);
    $tsReq['contents']['hex'] = seq($tsr[1]);
    $tsrn = reset($p);
    if($tsrn[0] == '06') {
      $tsReq['contents']['contentType'] = $tsrn[1];
      $tsrn = next($p);
    } else {
      return false;
    }
    if($tsrn[0] == 'a0') {
      $tsReqContent = asn1parse($tsrn[1]);
      $tsReq['contents']['content'] = $tsReqContent[0][1];
    } else {
      return false;
    }
  }
  return $tsReq;
}

function tsa_parsereqstd($binreq) {
  if(strlen($binreq) < 39) { // I calculate that minimum valid asn1 syntax request is 39 char
    return false;
  }
  $hex = bin2hex($binreq);
  $p = asn1parse($hex);
  if($p[0][0] != '30' || (substr($p[0][1], 0, 2) != '02' && substr($p[0][1], 0, 2) != '30')) {
    return false;
  }
  $timestampRequest = asn1parse($p[0][1]);

  $tsr = reset($timestampRequest);
  if($tsr[0] == '02') {
    $tsReq['version'] = $tsr[1];
    $tsr = next($timestampRequest);
  }
  if($tsr[0] == '30') {
    $p_messageImprint = asn1parse($tsr[1]);
    $p_messageImprint_algos = asn1parse($p_messageImprint[0][1]);
    $tsReq['messageImprint']['digestAlgorithm'] = $p_messageImprint_algos[0][1];
    $tsReq['messageImprint']['digestContent'] = $p_messageImprint[1][1];
    $tsr = next($timestampRequest);
  } else {
    return false;
  }
  if(@$tsr[0] == '06') {
    $tsReq['reqPolicy'] = $tsr[1];
    $tsr = next($timestampRequest);
  }
  if(@$tsr[0] == '02') {
    $tsReq['nonce'] = $tsr[1];
    $tsr = next($timestampRequest);
  }
  if(@$tsr[0] == '01') {
    $tsReq['certReq'] = $tsr[1];
    $tsr = next($timestampRequest);
  }
  return $tsReq;
}

function tsa_parsereq($rawReq, &$type) {
  if($return = tsa_parsereqapl($rawReq)) {
    $type = '2';
    return $return;
  } elseif ($return = tsa_parsereqstd($rawReq)) {
    $type = '1';
    return $return;
  } else {
    $type = false;
    return false;
  }
}

function getcrldate($crl) {
  $p = bin2hex($crl);
  $p = asn1parse($p);
  $p = asn1parse($p[0][1]);
  $p = asn1parse($p[0][1]);
//echo "<pre>";
//print_r($p);

  $index = false;
  if($p[0][0] == '02') {
    $index = 1;
  }
  $res['this'] = hex2bin($p[2+$index][1]);
  $res['next'] = hex2bin($p[3+$index][1]);
  if(strlen($res['this']) == 13 || strlen($res['this']) == 13 || strlen($res['next']) == 15 || strlen($res['next']) == 15) {
    if(substr($res['this'], -1) == "Z" && substr($res['next'], -1) == "Z") {
      return $res;
    }
  } else {
    return false;
  }
}
function difftime($in) {
  $y = substr($in, 0, 2);
  $m = substr($in, 2, 2);
  $d = substr($in, 4, 2);
  $h = substr($in, 6, 2);
  $i = substr($in, 8, 2);
  $s = substr($in, 10, 2);

  $totime = mktime($h, $i, $s, $m, $d, $y);
  $fromtime = mktime(date('H'), date('i'), date('s'), date('m'), date('d'), date('y'));
  
  return $totime-$fromtime;
}

function get_cert($certin) { // Read x.509 DER/PEM Certificate and return DER encoded x.509 Certificate
  if($rsccert = openssl_x509_read ($certin)) {
    openssl_x509_export ($rsccert, $cert);
    return x509_pem2der($cert);
  } else {
    $pem = x509_der2pem($certin);
    if($rsccert = openssl_x509_read ($pem)) {
      openssl_x509_export ($rsccert, $cert);
      return x509_pem2der($cert);
    } else {
      return false;
    }
  }
}

function x509_der2pem($der_cert) { // This function convert x509 der certificate to x509 PEM
  $x509_pem = "-----BEGIN CERTIFICATE-----\r\n";
  $x509_pem .= chunk_split(base64_encode($der_cert),64);
  $x509_pem .= "-----END CERTIFICATE-----\r\n";
  return $x509_pem;
}

function x509_pem2der($pem) {  // This function convert x509 pem certificate to x509 der
  $x509_der = false;
  if($x509_res = @openssl_x509_read($pem)) {
    openssl_x509_export ($x509_res,  $x509_pem);

    $arr_x509_pem = explode("\n", $x509_pem);
    $numarr = count($arr_x509_pem);
    $i=0;
    $cert_pem = false;
    foreach($arr_x509_pem as $val)  {
      if($i > 0 && $i < ($numarr-2))  {
        $cert_pem .= $val;
      }
      $i++;
    }
    $x509_der = base64_decode($cert_pem);
  }
  return $x509_der;
}

function x509_get_pubkeys($cert) {
  if($cert = get_cert($cert)) {
    $hexCrt = bin2hex($cert);
    $parse = asn1parse($hexCrt);
    $parse = asn1parse($parse[0][1]);
    $TBSCertificate = asn1parse($parse[0][1]);
    
    $TBSCertificate_signature = $TBSCertificate[2][1];
    $TBSCertificate_subjectPublicKeyInfo = seq($TBSCertificate[6][1]);
    $TBSCertificate_subject = seq($TBSCertificate[5][1]);
    $TBSCertificate_issuer = seq($TBSCertificate[3][1]);
    
    $pub_key = asn1parse($TBSCertificate_subjectPublicKeyInfo);
    $pub_key = asn1parse($pub_key[0][1]);
    $publicKey = hex2bin($pub_key[1][1]);
    switch(strtoupper(substr($TBSCertificate_signature, 0, -4))) {
      case '06092A864886F70D010104' : $alg = 'md5WithRSAEncryption'; break;
      case '06092A864886F70D010102' : $alg = 'md2WithRSAEncryption'; break;
      case '06092A864886F70D010103' : $alg = 'md4WithRSAEncryption'; break;
      case '06052B0E03020F'         : $alg = 'shaWithRSAEncryption'; break;
      case '06092A864886F70D010105' : $alg = 'sha1WithRSAEncryption'; break;
      case '06092A864886F70D01010E' : $alg = 'sha224WithRSAEncryption'; break;
      case '06092A864886F70D01010B' : $alg = 'sha256WithRSAEncryption'; break;
      case '06092A864886F70D01010C' : $alg = 'sha384WithRSAEncryption'; break;
      case '06092A864886F70D01010D' : $alg = 'sha512WithRSAEncryption'; break;
      default : $alg = false;
    }
    if($alg == false) {
      return false;
    }
    $result['hash'] = $alg;
    $result['issuerName'] = $TBSCertificate_issuer;
    $result['issuerNameHash'] = hash('sha1', hex2bin($TBSCertificate_issuer));
    $result['subjectName'] = $TBSCertificate_subject;
    $result['serialNumber'] = $TBSCertificate[1][1];
    $result['subjectNameHash'] = hash('sha1', hex2bin($TBSCertificate_subject));
    $result['subjectKeyHash'] = hash('sha1', substr($publicKey, 1));
    return $result;
  }
}

function asn1_header($str) {
  $len = strlen($str)/2;
  $ret = dechex($len);
  if(strlen($ret)%2 != 0) {
    $ret = "0$ret";
  }
  
  if($len > 127 && $len < 256)  {
    $ret = "81$ret";
  }
  if($len > 255 && $len < 65536)  {
    $ret = "82$ret";
  }
  if($len > 65535)  {
    $ret = "83$ret";
  }
  return $ret;
}
function INT($int)  {
  if(strlen($int)%2 != 0)  {
    $int = "0$int";
  }
  $int = "$int";
  $ret = "02".asn1_header($int).$int;
  return $ret;
}
function SEQ($hex)  {
  $ret = "30".asn1_header($hex).$hex;
  return $ret;
}
function SET($hex)  {
  $ret = "31".asn1_header($hex).$hex;
  return $ret;
}
function UTCTIME($time) {
  $ret = "170d".bin2hex($time)."5a";
  return $ret;
}
function EXPLICIT($num, $hex)  {
  $ret = "a$num".asn1_header($hex).$hex;
  return $ret;
}
function UTF8($str) {
  $ret = "0c".asn1_header(bin2hex($str)).bin2hex($str);
  return $ret;
}
function OBJ($hex)  {
  $ret = "06".asn1_header($hex).$hex;
  return $ret;
}
function OCT($hex)  {
  $ret = "04".asn1_header($hex).$hex;
  return $ret;
}
function GENTIME($time)  {
  $ret = "180f".bin2hex($time)."5a";
  return $ret;
}

?>