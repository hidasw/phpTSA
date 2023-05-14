<?php
/*############## This script written by Hida <mn_hda@yahoo.com> ###################*/

/* Recode at 21:51 Sore 28/01/2009 */
/* Recode at 19:55 Sore 01/03/2009 */
/* Recode at 21:46 Sore 23/03/2009 */
/* Recode at Minggu 14 Mei 2023 21:05:35 Sore */

define("TSA_NAME", "TSA0");
if(array_key_exists('nonce', $PARSED_REQ)) { // cek nonce
  $reqNonce = int($PARSED_REQ['nonce']);
} else {
  $reqNonce = false;
}

$crlAttached = false;
if(array_key_exists('crls', $TSA)) {
  foreach($TSA['crls'] as $crlnum=>$crl) {
        $parseCrl = getcrldate($crl);
        $diffTime = difftime($parseCrl['next']);
        if($diffTime < 0) {
          tsalog("CRL \"$crlnum\" expired!", 'w');
        }
        $crlAttached .= bin2hex($crl);
  }
  $crlAttached = explicit("1", $crlAttached);
}

if(!$signerCertId = x509_get_pubkeys($TSA['signer'])) {
  tsalog("x509_get_pubkeys failed\nOn ".__FILE__."(".__LINE__.")", 'e');
  exit;
}
$TSAserial = $TSA['serial']+1;

$utcdate = gmdate("ymdHis");
$gendate = gmdate("YmdHis");
$genUtime = microtime(true);
$microTime = substr($genUtime, strpos($genUtime, '.')+1);
$TimeStamp = $gendate.'.'.$microTime;
$TimeStamp = $gendate;

$TimeStampAccuracy = false; // until now 00:10 Esuk 09/07/2009 still not implement. i dont too know about this field structure
$TimeStampAccuracy = seq( // add @ 07:11 Esuk Kamis 16 Juli 2009
                        '02013c'
                        //'800203e8'.
                        //'810203e8'
                        );

$TSTInfo = seq(
              int("1").
              obj(oid2hex(TSA_POLICY)).
              seq(
                  seq(
                      obj($PARSED_REQ['messageImprint']['digestAlgorithm']).
                      OBJ_null
                      ).
                  oct($PARSED_REQ['messageImprint']['digestContent'])
                  ).
              int($TSAserial).
              gentime($TimeStamp).
              //$TimeStampAccuracy.
              $reqNonce
              );

$TSTInfo_hash = hash(TSA_HASHALGORITHM, hex2bin($TSTInfo)); // custom hash dr DER encoding TSTinfo
$certSignerFingerprint = hash('sha1', get_cert($TSA['signer'])); // sha1 hash dr DER encoding sertifikat TSA

$signedinfo = seq(
                  OBJ_pkcs9_contentType.
                  set(
                      OBJ_id_smime_ct_TSTInfo
                      )
                  ).
              seq(
                  OBJ_pkcs9_signingTime.
                  set(
                      utctime($utcdate)
                      )
                  ).
              seq(
                  OBJ_pkcs9_messageDigest.
                  set(
                      oct($TSTInfo_hash)
                      )
                  ).
              seq(
                  OBJ_id_smime_aa_signingCertificate.
                  set(
                      seq(
                          seq(
                              seq(
                                  oct($certSignerFingerprint).
                                  seq(
                                      seq(
                                          explicit("4", 
                                                  $signerCertId['issuerName']
                                                  )
                                          ).
                                      int($signerCertId['serialNumber'])
                                      )
                                  )
                              )
                          )
                      )
                  );

$signedinfo_hash = hash(TSA_HASHALGORITHM,
                                          hex2bin(
                                                  set(
                                                      $signedinfo
                                                      )
                                                  )
                        );

$to_encrypt = seq(
                  seq(
                      constant('OBJ_'.TSA_HASHALGORITHM).
                      OBJ_null
                      ).
                  oct($signedinfo_hash)
                  );

if(!@openssl_private_encrypt(hex2bin($to_encrypt), $crypted, $TSA['signer'])) {
  tsalog("Failed to signing\n".__FILE__."(".__LINE__.")", 'e');
  exit;
}

$extraCerts = false;
if(array_key_exists('extracerts', $TSA)) {
  foreach($TSA['extracerts'] as $extcrt) {
    $extraCerts .= get_cert($extcrt);
  }
}

$tst = seq(
          seq(
              int("0").
              seq(
                  utf8("TimeStamp by Hida....Ok")
                  )
              ).
          seq(
              OBJ_pkcs7_signed.
              explicit("0",
                          seq(
                              int("3").
                              set(
                                  seq(
                                      constant('OBJ_'.TSA_HASHALGORITHM).
                                      OBJ_null
                                      )
                                  ).
                              seq(
                                  OBJ_id_smime_ct_TSTInfo.
                                  explicit("0",
                                          oct($TSTInfo)
                                          )
                                  ).
                              explicit("0",
                                      bin2hex(get_cert($TSA['signer'])).
                                      bin2hex($extraCerts) // Sertifikat utk disertakan +
                                      ).
                                      $crlAttached.  // Crl utk disertakan +
                              set(
                                  seq(
                                      int("1").
                                      seq(
                                          $signerCertId['issuerName'].
                                          int($signerCertId['serialNumber'])
                                         ).
                                      seq(
                                          constant('OBJ_'.TSA_HASHALGORITHM).
                                          OBJ_null
                                         ).
                                      explicit("0",
                                              $signedinfo
                                              ).
                                      seq(
                                          OBJ_rsaEncryption.
                                          OBJ_null
                                         ).
                                      oct(
                                          bin2hex($crypted) // Hasil enkripsi (TSA signature)
                                         )
                                     )
                                 )
                             )
                      )
             )
          );

$respOut = hex2bin($tst);
header('Content-Length: '.strlen($respOut));
// $respOut = base64_encode($respOut);

echo $respOut; // Tampilkan hasil TimeStamp

$h = fopen(getcwd()."/serial.txt", "w");
fwrite($h, $TSAserial);
fclose($h);

// $h = fopen(getcwd()."/lastReq0.der", "w");
// fwrite($h, $req);
// fclose($h);

// $h = fopen(getcwd()."/lastResp0.der", "w");
// fwrite($h, $respOut);
// fclose($h);



tsalog("Response Successfull. Hash alg:".TSA_HASHALGORITHM, 'i');

?>