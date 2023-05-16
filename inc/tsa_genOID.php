<?php
//include 'readOID.php'; // need
function trimhex($h) {
  if(strlen($h) < 2) {
    $h = "0$h";
  }
  return $h;
}
function oid2hex($oid) {
  $arr = explode(".", $oid);
  $i = 0;
  $r = false;
  foreach($arr as $val) {
    if($i > 1) {
      if($val >= 128) {
        $r = g($val);
        foreach($r as $val) {
          $ret .= $val;
        }
      } else {
        $ret .= trimhex(dechex($val));
      }
    } else {
      if($i == 0) {
        if($val == 0) {
          $add = 0;
        }
        if($val == 1) {
          $add = 40;
        }
        if($val == 2) {
          $add = 80;
        }
      }
      if($i == 1) {
        if($val >= 48) {
          $special = g($val+80);
          foreach($special as $v) {
            $ret .= $v;
          }
        } else {
          $ret = trimhex(dechex($val+$add));
        }
      }
    }
    $i++;
  }
  return $ret;
}
function a($dec, &$div, &$rem) {
  $div = floor($dec/128);
  $rem = (($dec/128)-$div)*128;
  if($div <= 0) {
    return false;
  } else {
    return true;
  }
}
function g($dec) {
  $i = 0;
  while(a($dec, $d, $r) != false) {
    $hida = $r+128;
    if($i == 0) {
      $hida = $r;
    }
    //echo "$d => $hida\n";
    $dec = $d;
    $ret[$d] = $r;
    $i++;
  }
  $i = 1;
  $end = count($ret);
  foreach($ret as $k => $v) {
    $hida = $v+128;
    if($i == 1) {
      $hida = $v;
    }
    //echo "$hida\n";
    $hex[] = trimhex(dechex($hida));
    if($i == $end) {
      $hida = $k+128;
      //echo "$hida\n";
      $hex[] = trimhex(dechex($hida));
    }
    $i++;
  }
  //echo "last : ".count($ret)."\n";
  $hex = array_reverse($hex);;
  return $hex;
}
?>