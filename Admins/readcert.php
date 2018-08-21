<?php
// THIS SCRIPT IS FOR READ X.509 CERTIFICATE STRUCTURE
// SELF CREATED BY HIDA <mn_hda@yahoo.com>
// FILE : "C:\Inetpub\wwwroot\Includes\readcert.php"
// finishing by hida at 08:13 Esuk Sabtu 06 Desember 2008
// Recoding by Hida at 20:09 Sore Rabu 25 Februari 2009
// Recoding by Hida at 20:04 Sore Minggu 01 Maret 2009

// this may still containts some bugs while read some certificate 
// with foreign extensions

//include 'asn1_function.php';
//include 'asn1_parser.php';
//include 'OIDv.php';
//include 'keyUsage.php';
//include 'readOID.php';
function hida_readcert($cert_in) {
  if(!$der = get_cert($cert_in)) {
    //echo "error hida : function ". __FUNCTION__.", input is not x509 der/pem certificate. ".__FILE__."\n";
    return false;
  }
  $hex = bin2hex($der);
  $prs = asn1parse($hex);
  $prs = asn1parse($prs[0][1]);
  foreach($prs as $k=>$val) {
    if($k == 0) {
      $cert['tbsCertificate']['hex'] = seq($val[1]);
      $prs = asn1parse($val[1]);
        $v = reset($prs);
        if($v[0] == 'a0') {
          $valu = asn1parse($v[1]);
          $cert['tbsCertificate']['version'] = $valu[0][1];
          $v = next($prs);
        }
        if($v[0] == '02') {
          $cert['tbsCertificate']['serialNumber'] = $v[1];
          $v = next($prs);
        }
        if($v[0] == '30') {
          $pSignature = asn1parse($v[1]);
          $cert['tbsCertificate']['signature'] = toconst(readoid($pSignature[0][1]));
          $v = next($prs);
        }
        if($v[0] == '30') {
          $cert['tbsCertificate']['issuer']['hex'] = seq($v[1]);
          $UissuerHash = hash('md5', hex2bin(seq($v[1])));
          $UissuerHash = substr($UissuerHash, 0, 8);
          $UissuerHash = str_split($UissuerHash, 2);
          $UissuerHash = array_reverse($UissuerHash);
          $UissuerHash = implode("", $UissuerHash);
          $cert['tbsCertificate']['hash']['issuer'] = $UissuerHash; // added at 13:41 Sore 14/06/2009
          //$pIssuer = asn1parse($v[1]);
          //foreach($pIssuer as $v) {
          //  $dn = (asn1parse($v[1]));
          //  $dn = (asn1parse($dn[0][1]));
          //  $cert['tbsCertificate']['issuer'][toconst(readoid($dn[0][1]))] = hex2bin($dn[1][1]);
          //}
          //$v = next($prs);
          $pissuer = asn1parse($v[1]);
          foreach($pissuer as $v) {
            $dn = asn1parse($v[1]);
            if(count($dn) > 1) {
              foreach($dn as $mtpleDn) {
                $mtple = asn1parse($mtpleDn[1]);
                $tbsCertificateissuer['multi'][toconst(readoid($mtple[0][1]))][] = hex2bin($mtple[1][1]);
              }
            } else {
              $dn = (asn1parse($dn[0][1]));
              $tbsCertificateissuer[toconst(readoid($dn[0][1]))][] = hex2bin($dn[1][1]);
            }
          }
          foreach($tbsCertificateissuer as $tbsCertificateissuerK=>$tbsCertificateissuerV) {
            if($tbsCertificateissuerK == 'multi') {
              if(count($tbsCertificateissuerV) == 1) {
                $multi = $tbsCertificateissuerV[0];
              } else {
                foreach($tbsCertificateissuerV as $multiK=>$multiV) {
                  if(count($multiV) > 1) {
                    $multi[$multiK] = $multiV;
                  } else {
                    $multi[$multiK] = $multiV[0];
                  }
                }
              }
              $cert['tbsCertificate']['issuer']['multi'] = $multi;
            } else {
              if(count($tbsCertificateissuerV) == 1) {
                $cert['tbsCertificate']['issuer'][$tbsCertificateissuerK] = $tbsCertificateissuerV[0];
              } else {
                $cert['tbsCertificate']['issuer'][$tbsCertificateissuerK] = $tbsCertificateissuerV;
              }
            }
          }
          $v = next($prs);
        }
        if($v[0] == '30') {
          $pValidity = asn1parse($v[1]);
          $validFrom = hex2bin($pValidity[0][1]);
          $validTo = hex2bin($pValidity[1][1]);
          $cert['tbsCertificate']['validity']['notBefore'] = $validFrom;
          $cert['tbsCertificate']['validity']['notAfter'] = $validTo;
          $v = next($prs);
        }
        if($v[0] == '30') {
          //$pSubject = asn1parse($v[1]);
          //$cert['tbsCertificate']['subject']['hex'] = seq($v[1]);
          //foreach($pSubject as $v) {
          //  $dn = (asn1parse($v[1]));
          //  $dn = (asn1parse($dn[0][1]));
          //  $tbsCertificateSubject[toconst(readoid($dn[0][1]))][] = hex2bin($dn[1][1]);
          //}
          //foreach($tbsCertificateSubject as $tbsCertificateSubjectK=>$tbsCertificateSubjectV) {
          //  if(count($tbsCertificateSubjectV) == 1) {
          //    $cert['tbsCertificate']['subject'][$tbsCertificateSubjectK] = $tbsCertificateSubjectV[0];
          //  } else {
          //    $cert['tbsCertificate']['subject'][$tbsCertificateSubjectK] = $tbsCertificateSubjectV;
          //  }
          //}
          //$v = next($prs);
          $pSubject = asn1parse($v[1]);
          $UsubjectHash = hash('md5', hex2bin(seq($v[1])));
          $UsubjectHash = substr($UsubjectHash, 0, 8);
          $UsubjectHash = str_split($UsubjectHash, 2);
          $UsubjectHash = array_reverse($UsubjectHash);
          $UsubjectHash = implode("", $UsubjectHash);
          $cert['tbsCertificate']['hash']['subject'] = $UsubjectHash; // added at 13:41 Sore 14/06/2009
          $cert['tbsCertificate']['subject']['hex'] = seq($v[1]);
          foreach($pSubject as $v) {
            $dn = asn1parse($v[1]);
            if(count($dn) > 1) {
              foreach($dn as $mtpleDn) {
                $mtple = asn1parse($mtpleDn[1]);
                $tbsCertificateSubject['multi'][toconst(readoid($mtple[0][1]))][] = hex2bin($mtple[1][1]);
              }
            } else {
              $dn = (asn1parse($dn[0][1]));
              $tbsCertificateSubject[toconst(readoid($dn[0][1]))][] = hex2bin($dn[1][1]);
            }
          }
          foreach($tbsCertificateSubject as $tbsCertificateSubjectK=>$tbsCertificateSubjectV) {
            if($tbsCertificateSubjectK == 'multi') {
              if(count($tbsCertificateSubjectV) == 1) {
                $multi = $tbsCertificateSubjectV[0];
              } else {
                foreach($tbsCertificateSubjectV as $multiK=>$multiV) {
                  if(count($multiV) > 1) {
                    $multi[$multiK] = $multiV;
                  } else {
                    $multi[$multiK] = $multiV[0];
                  }
                }
              }
              $cert['tbsCertificate']['subject']['multi'] = $multi;
            } else {
              if(count($tbsCertificateSubjectV) == 1) {
                $cert['tbsCertificate']['subject'][$tbsCertificateSubjectK] = $tbsCertificateSubjectV[0];
              } else {
                $cert['tbsCertificate']['subject'][$tbsCertificateSubjectK] = $tbsCertificateSubjectV;
              }
            }
          }
          $v = next($prs);
        }
        if($v[0] == '30') {
          $cert['tbsCertificate']['subjectPublicKeyInfo']['hex'] = seq($v[1]);
          $p_subjectPublicKeyInfo = asn1parse($v[1]);
          $p_subjectPublicKeyInfo_alg = asn1parse($p_subjectPublicKeyInfo[0][1]);
          $p_subjectPublicKeyInfoParse0 = asn1parse(substr($p_subjectPublicKeyInfo[1][1], 2));
          $p_subjectPublicKeyInfoParse = asn1parse($p_subjectPublicKeyInfoParse0[0][1]);
          $cert['tbsCertificate']['subjectPublicKeyInfo']['signAlg'] = toconst(readoid($p_subjectPublicKeyInfo_alg[0][1]));
          if($p_subjectPublicKeyInfo_alg[0][1] == '2b0e03020c') { // dsaEncryption-old (OBJ_dsa_2)
            $cert['tbsCertificate']['subjectPublicKeyInfo']['Modulus'] = $p_subjectPublicKeyInfoParse0[0][1];
            $subjectPublicKeykeyLength = strlen(hex2bin(ltrim($p_subjectPublicKeyInfoParse0[0][1], '00')))*8;
          } else {
            $cert['tbsCertificate']['subjectPublicKeyInfo']['Modulus'] = $p_subjectPublicKeyInfoParse[0][1];
            $cert['tbsCertificate']['subjectPublicKeyInfo']['publicExponent'] = $p_subjectPublicKeyInfoParse[1][1];
            $subjectPublicKeykeyLength = strlen(hex2bin(substr($p_subjectPublicKeyInfoParse[0][1], 2)))*8;
          }
          $cert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'] = $p_subjectPublicKeyInfo[1][1];
          $cert['tbsCertificate']['subjectPublicKeyInfo']['keyLength'] = $subjectPublicKeykeyLength;
          $cert['tbsCertificate']['subjectPublicKeyInfo']['hash']['sha1'] = hash('sha1', substr(hex2bin($p_subjectPublicKeyInfo[1][1]),1));
          $cert['tbsCertificate']['subjectPublicKeyInfo']['hash']['md5'] = hash('md5', substr(hex2bin($p_subjectPublicKeyInfo[1][1]),1));
          $cert['tbsCertificate']['subjectPublicKeyInfo']['hash']['md4'] = hash('md4', substr(hex2bin($p_subjectPublicKeyInfo[1][1]),1));
          $cert['tbsCertificate']['subjectPublicKeyInfo']['hash']['md2'] = hash('md2', substr(hex2bin($p_subjectPublicKeyInfo[1][1]),1));
          $v = next($prs);
        }
        if($v[0] == 'a3') {
          $p_extensions = asn1parse($v[1]);
          $p_extensions = asn1parse($p_extensions[0][1]);
          foreach($p_extensions as $v) {
            $ev = asn1parse($v[1]);
            $critical = false;
            $value = @$ev[1][1];
            if(count($ev) == 3) {
              if($ev[1][1] == '00') {
                $critical = 'notcritical';
                $value = $ev[2][1];
              }
              if($ev[1][1] == 'ff') {
                $critical = 'critical';
                $value = $ev[2][1];
              }
            }
            if(count($ev) < 2) {
              $cert['tbsCertificate']['extensions'][toconst(readoid($ev[0][1]))] = false;
            } else {
              $value = parseExts(readoid($ev[0][1]), $value);
              $cert['tbsCertificate']['extensions'][toconst(readoid($ev[0][1]))]['critical'] = $critical;
              $cert['tbsCertificate']['extensions'][toconst(readoid($ev[0][1]))]['value'] = $value;
            }
          }
        }
    }
    if($k == 1) {
      $valu = asn1parse($val[1]);
      $cert['signatureAlgorithm'] = toconst(readoid($valu[0][1]));
      $matchDigestAlg = str_replace("OBJ_", "", str_replace("WithRSAEncryption", "", $cert['signatureAlgorithm']));
      if(!in_array($matchDigestAlg, hash_algos())) {
        echo "Readcert: unsupported hash algorithm '$matchDigestAlg'\n";
        return false;
      }
      $cert['tbsCertificate']['subjectPublicKeyInfo']['hash']['match'][$matchDigestAlg] = hash($matchDigestAlg, substr(hex2bin($p_subjectPublicKeyInfo[1][1]), 1));
    }
    if($k == 2) {
      $cert['signatureValue'] = $val[1];
    }
  }
  $baseFields = array('tbsCertificate','signatureAlgorithm','signatureValue');
  $basicFields = array('serialNumber','signature','issuer','validity','subject','subjectPublicKeyInfo');
  foreach($baseFields as $baseFieldsK) {
    if(!array_key_exists($baseFieldsK, $cert)) {
      echo  __FUNCTION__." :not complete Certificate field. \"$baseFieldsK\" field not exists";
      return false;
    }
  }
  foreach($basicFields as $basicFieldsK) {
    if(!array_key_exists($basicFieldsK, $cert['tbsCertificate'])) {
      echo __FUNCTION__." :not complete tbsCertificate field. \"$basicFieldsK\" field not exists";
      return false;
    }
  }
  return $cert;
}
function parseExts($oid, $val) {
  $ret = $val;
  if($oid == '2.5.29.35') {
    $ret = false;
    $ret['hex'] = $val;
    $prs = asn1parse($val);
    $prs1 = asn1parse($prs[0][1]);
    foreach($prs1 as $akiV) {
      if($akiV[0] == '80') {
        $ret['keyIdentifier'] = $akiV[1];
      }
      if($akiV[0] == 'a1') {
        $authorityCertIssuer = asn1parse($akiV[1]);
        if($authorityCertIssuer[0][0] == 'a4') {
          $authorityCertIssuerHEX = $authorityCertIssuer[0][1];
          $authorityCertIssuer = asn1parse($authorityCertIssuer[0][1]);
          $authorityCertIssuer = asn1parse($authorityCertIssuer[0][1]);
          foreach($authorityCertIssuer as $GeneralNames) {
            $GeneralNamesDNP = asn1parse($GeneralNames[1]);
            $GeneralNamesDNP = asn1parse($GeneralNamesDNP[0][1]);
            $GeneralNamesDN[toconst(readoid($GeneralNamesDNP[0][1]))] = hex2bin($GeneralNamesDNP[1][1]);
          }
          $ret['authorityCertIssuer'] = $GeneralNamesDN;
          //$ret['authorityCertIssuer']['hex'] = $authorityCertIssuerHEX;
        } else {
          $ret['authorityCertIssuer'] = $akiV[1];
        }
      }
      if($akiV[0] == '82') {
        $ret['authorityCertSerialNumber'] = $akiV[1];
      }
    }
    //$ret = $ret[0][1];
  }
  if($oid == '2.5.29.14') {
    $ret = asn1parse($val);
    $ret = $ret[0][1];
  }
  if($oid == '2.5.29.15') { // OBJ_key_usage
    $ret = asn1parse($val);
    $ret = parse_ku($ret[0][1]);
  }
  if($oid == '1.3.6.1.5.5.7.1.1') { // OBJ_info_access
    $p = asn1parse($val);
    $rets = asn1parse($p[0][1]);
    foreach($rets as $va) {
      $p_aia = asn1parse($va[1]);
      $return[toconst(readoid($p_aia[0][1]))][] = hex2bin($p_aia[1][1]);
    }
    $ret = $return;
  }
  if($oid == '2.5.29.31') { // OBJ_crl_distribution_points
    $p = asn1parse($val);
    $rets = asn1parse($p[0][1]);
    $rets = asn1parse($rets[0][1]);
    $rets = asn1parse($rets[0][1]);
    $rets = asn1parse($rets[0][1]);
    foreach($rets as $v) {
      $return[] = hex2bin($v[1]);
    }
    $ret = $return;
  }
  if($oid == '2.5.29.37') { // OBJ_ext_key_usage
    $ret = asn1parse($val);
    $ret = asn1parse($ret[0][1]);
    foreach($ret as $v) {
      $return[] = toconst(readoid($v[1]));
    }
    $ret = $return;
  }
  if($oid == '2.5.29.19') { // OBJ_basic_constraints
    if($val == 3000) {
      $ret = "endEntity";
    } else {
      $ret = asn1parse($val);
      $ret = asn1parse($ret[0][1]);
      foreach($ret as $bc) {
        if($bc[0] == '01') {
          if($bc[1] == 'ff') {
            $ret = "CA,pathlen:";
          }
        }
        if($bc[0] == '02') {
          $ret .= $bc[1];
        }
      }
    }
  }
  return $ret;
}
?>