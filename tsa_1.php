<?php
// Last change at 20:50 Sore Minggu 01 Maret 2009
// Last change at 14:30 Sore Senin 23 Maret 2009 req not based of content-type header,
// but based on req structure

// Last change at 21:30 Sore Rabu 08 Juli 2009
// Last change at Minggu 14 Mei 2023 21:05:45 Sore

define("TSA_NAME", "TSA1");
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
   $crlAttached = explicit('1',
                              $crlAttached
                              );
}

if(!$signerCertId = x509_get_pubkeys($TSA['signer'])) {
  tsalog("x509_get_pubkeys failed\nOn ".__FILE__."(".__LINE__.")", 'e');
  exit;
}
$TimeStamp = gmdate('ymdHis');
$contentHash = sha1(hex2bin($PARSED_REQ['contents']['content']));
$authenticatedAttributes = seq(
                               OBJ_pkcs9_contentType.
                               set(
                                   OBJ_pkcs7_data
                                   )
                               ).
                           seq(
                               OBJ_pkcs9_signingTime.
                               set(
                                   utctime($TimeStamp)
                                   )
                               ).
                           seq(
                               OBJ_pkcs9_messageDigest.
                               set(
                                   oct($contentHash)
                                   )
                               );

$authenticatedAttributes_hash = sha1(
                                     hex2bin(
                                             set(
                                                 $authenticatedAttributes
                                                 )
                                             )
                                     );

$to_encrypt = seq(
                  seq(
                      OBJ_sha1.
                      OBJ_null
                      ).
                  oct($authenticatedAttributes_hash)
                  );

if(!@openssl_private_encrypt(hex2bin($to_encrypt), $crypted, $TSA['signer'])) {
  tsalog("Failed to signing\n".__FILE__."(".__LINE__.")", 'e');
  exit;
}

$extraCerts = false;
if(array_key_exists('extracerts', $TSA)) {
  foreach($TSA['extracerts'] as $extCrt) {
    $extraCerts .= get_cert($extCrt);
  }
}
$res = seq(
          OBJ_pkcs7_signed.
          explicit('0',
                  seq(
                      int('1').
                      set(
                          seq(
                              OBJ_sha1.
                              OBJ_null
                              )
                          ).
                      $PARSED_REQ['contents']['hex'].
                      explicit('0',
                              bin2hex(get_cert($TSA['signer'])).
                              bin2hex($extraCerts)
                              ).
                              $crlAttached.
                      set(
                          seq(
                              int('1').
                              seq(
                                  $signerCertId['issuerName'].
                                  int($signerCertId['serialNumber'])
                                  ).
                              seq(
                                  OBJ_sha1.
                                  OBJ_null
                                  ).
                              explicit('0',
                                      $authenticatedAttributes
                                      ).
                              seq(
                                  OBJ_rsaEncryption.
                                  OBJ_null
                                  ).
                              oct(
                                  bin2hex($crypted)
                                  )
                              )
                          )
                      )
                  )
          );

$response = hex2bin($res);
$respOut = base64_encode($response);
echo $respOut;

// $h = fopen(getcwd().'/lastReq1.der', 'w');
// fwrite($h, $req);
// fclose($h);

// $h = fopen(getcwd().'/lastResp1.der', 'w');
// fwrite($h, chunk_split($respOut));
// fclose($h);

tsalog("Response Successfull. Hash alg:".TSA_HASHALGORITHM, 'i');
?>