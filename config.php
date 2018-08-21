<?php
function parseCfg($cfgFile) {
  $p = file($cfgFile);
  $currCharStr = false;
  foreach($p as $k=>$v) {
    $currCharStr .= $v;
    $pattern = "/^(\s*|\t*)$/";
    $skip = preg_match ($pattern, $v, $matches);
    if($skip == 0) {
      $pattern = "/^(\s*|\t*)(;+|#+)/";
      $skip = preg_match ($pattern, $v, $matches);
      if($skip == 0) {
        $pattern = "/^\s+(.+)/";
        $skip = preg_match ($pattern, $v, $matches);
        $value = $v;
        if($skip == 1) {
          $value = $matches[1];
        }
        $pattern = "/^(\s*|\t*)(\[{1,1}\t*\s*(\w+)\t*\s*\]{1,1})(\s*|\t*)$/";
        $skip = preg_match ($pattern, $value, $matches);
        if($skip == 1) {
          $result[$matches[3]]['position'] = strlen($currCharStr);
        } else {
          $pattern = "/^\t*\s*(\w*.*)(\t*\s*)(={1,1})\t*\s*(.*)\t*\s*$/";
          $skip = preg_match ($pattern, $value, $matches);
          $patternSkipValueComment = "/^(.*)(#+)(.*)$/";
          $SkipValueComment = preg_match ($patternSkipValueComment, $matches[4], $matchesSkipValueComment);
          $resultValue = $matches[4];
          if($SkipValueComment == 1) {
            $resultValue = $matchesSkipValueComment[1];
          }
          $value = trim($matches[1])."=".trim($resultValue, " \t");
          $result[] = $value;
        }
      }
    }
  }
  $revsResult = array_reverse($result);
  $save = array();
  foreach($revsResult as $rk=>$rv) {
    if(is_array($rv)) {
      $save['position'] = $rv['position'];
      $endResult[$rk] = $save;
      $save = array();
    } else {
      $explodeValue = explode("=", $rv);
      $save[trim($explodeValue[0])] = trim($explodeValue[1]);
    }
  }
  $startNotArray = false;
  foreach($result as $rk=>$rv) {
    if(!is_array($rv)) {
      $explodeValue = explode("=", $rv);
      $startNotArray[$explodeValue[0]] = $explodeValue[1];
    } else {
      break;
    }
  }
  if($startNotArray != false) {
    $endResult[0] = $startNotArray;
  }
  $arrParsed = array_reverse($endResult);
  return $arrParsed;
}

function tsa_config($cfgFile) {
  if(!$tsa_config = parsecfg($cfgFile)) {
    return "can't parse tsa.cfg.";
  }
  if(!array_key_exists('database', $tsa_config) || !array_key_exists('common', $tsa_config)) {
    return "config section error.";
  }
  $cfg_key = array('dbhost','dbport','dbusername','dbpassword','dbname','tablelogs','tablesigners','tableextracerts','tablecrls');
  $cfg_keyCmn = array('hashalgorithm','policy');
  foreach($cfg_key as $confkey) {
    if(!array_key_exists($confkey, $tsa_config['database'])) {
      return "Section '[database]', field $confkey missing";
    }
    define("TSA_".strtoupper($confkey), $tsa_config['database'][$confkey]);
  }
  foreach($cfg_keyCmn as $confkey) {
    if(!array_key_exists($confkey, $tsa_config['common'])) {
      return "Section '[common]', field $confkey missing";
    }
    define("TSA_".strtoupper($confkey), $tsa_config['common'][$confkey]);
  }
  return $tsa_config;
}
?>