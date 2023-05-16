<?php
// create 03:29 Esuk 03/09/2009
function tsaLogfile($data, $filename) {
	$t = microtime(true);
	$micro = sprintf("%06d",($t - floor($t)) * 1000000);
	$d = new DateTime( date('Y-m-d H:i:s.'.$micro, intval($t)) );
	$d->setTimezone(new DateTimeZone('Asia/Jakarta'));
	$date = $d->format("Y-m-d_H.i.s.u");
	$h = fopen(realpath('.').'/log/'.$date.'_'.$filename,'w');
	fwrite($h, $data);
	fclose($h);
	
} // 14:48 Sore 16/05/2023


function tsaLog($str, $type = 'i') { // 12:40 Sore 09/07/2009
  $dateFormat = date("D M d Y H:i:s");
  if(!defined('TSA_NAME')) {
    $tsaName = 'MAIN';
  } else {
    $tsaName = TSA_NAME;
  }
  switch($type) {
    case 'e' : $errType = 'error'; break;
    case 'w' : $errType = 'warning'; break;
    case 'i' : $errType = 'info'; break;
    case 'n' : $errType = 'info'; break;
    default : $errType = 'notice';
  }
  $clientIpAddress = $_SERVER['REMOTE_ADDR'];
  $clientHostName = gethostbyaddr($_SERVER['REMOTE_ADDR']);
  if($clientHostName == $clientIpAddress) {
    $clientHostName = 'unknownHost';
  }
  
  $prependLog = "[$dateFormat] [$tsaName] [$errType] [client $clientHostName ($clientIpAddress)]";
  $explodeStr = explode("\n", $str);
  $prependLogLen = strlen($prependLog);
  $prependLogIdent = str_repeat(' ', $prependLogLen+1);
  $strLog = false;
  foreach($explodeStr as $lineNum=>$strLine) {
    if($lineNum == 0) {
      $strLog .= rtrim($strLine)."\r\n";
    } else {
      $strLog .= $prependLogIdent.rtrim($strLine)."\r\n";
    }
  }
  $log = "$prependLog $strLog";
  if(is_writable(getcwd().'/tsa.err')) {
    $handle = fopen(getcwd().'/tsa.err', 'a');
    fwrite($handle, $log);
    fclose($handle);
  } else {
    $handle = @fopen(getcwd().'/tsa.err', 'a');
    fwrite($handle, $log);
    fclose($handle);
    if($type == 'e') {
      echo "<pre>\nCan't write log to file \"ocsp.err\", please check file permission. OCSP log return error, these error is:\n";
      echo "$log\n</pre>";
    }
  }
}
?>