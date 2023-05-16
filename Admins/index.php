<html>

<head>
<meta http-equiv="Content-Language" content="en-us">
<meta name="GENERATOR" content="Microsoft FrontPage 5.0">
<meta name="ProgId" content="FrontPage.Editor.Document">
<meta http-equiv="Content-Type" content="text/html; charset=windows-1252">
<link rel='icon' href='http://www.hdalabs.net/img/c.ico' type='image/x-icon'/>
<link rel='shortcut icon' href='http://www.hdalabs.net/img/c.ico' type='image/x-icon'/>
<title>.::TSA Administration::.</title>

<style>
  a { color: #2583ad; text-decoration: none; }
  a:hover { color: #33ffff; }
  body {
    background: #cccccc;
    color: #33300;
    font-family: "Lucida Grande", Verdana, Arial, "Bitstream Vera Sans", sans-serif;
    width: 700px;
    padding: 1em 2em;
    -moz-border-radius: 11px;
    -khtml-border-radius: 11px;
    -webkit-border-radius: 11px;
    border-radius: 11px;
    border: 0px solid #dfdfdf;
}
</style>


</head>
<body>
<pre style="font-family: Arial; font-size: 10pt"><h1 align="center"><font size="4">TimeStamp Server Administration page</font></h1><?php
//include '../parseCfg.php';
include '../inc/tsa_config.php';
$tsaConfig = tsa_config('../tsa.cfg');
if(!is_array($tsaConfig)) {
  echo "ERROR: $tsaConfig";
  exit;
}
if(@$_GET['v'] == 'main' || !@$_GET['v']) {
echo"<b><a href='?v=log'>Log</a></b><div id='topmsg'></div>
  <fieldset style='border:2px solid #3355aa; padding:2; background-color:#00dd00'>
  <legend><font size='4'>Current TSA Configuration</font></legend>
  <table id='AutoNumber1' style='FONT-SIZE: 9pt; BORDER-COLLAPSE: collapse' borderColor='#111111' cellSpacing='0' cellPadding='0' width='100%' border='1'>
";
foreach($tsaConfig as $tsaConfigSectionK=>$tsaConfigSectionV) {
  if($tsaConfigSectionK == 'database') {
    foreach(array_reverse($tsaConfigSectionV) as $k=>$v) {
      if($k != 'position') {
echo "    <tr>
      <td width='24%'>$k</td>
      <td width='76%'>
      <input class='textbox' id='$k' size='64' value='$v' name='$k'></td>
    </tr>";
      }
    }
  }
  if($tsaConfigSectionK == 'common') {
    foreach(array_reverse($tsaConfigSectionV) as $k=>$v) {
      if($k != 'position') {
echo "    <tr>
      <td width='24%'>$k</td>
      <td width='76%'>
      <input class='textbox' id='$k' size='64' value='$v' name='$k'></td>
    </tr>";
      }
    }
  }
}
echo "    <tr>
      <td width='24%'></td>
      <td width='76%'><br><button onClick=\"hact();\">Save Configurations</button></td>
    </tr>";

echo "  </table></fieldset>";
//print_r($tsaConfig);

echo"
  <fieldset style='border:2px solid #3355aa; padding:2; background-color:#00dd00'>
  <legend><font size='4'>TSA Certificate & CRL</font></legend>
    Signer Certificate  <input type='file' class='textbox' id='dn_cn' size='64' value='".TSA_DBHOST."' name='dn[cn]'>\n
    Extra Certificate  <input type='file' class='textbox' id='dn_cn' size='64' value='".TSA_DBHOST."' name='dn[cn]'>\n
    CRL  <input type='file' class='textbox' id='dn_cn' size='64' value='".TSA_DBHOST."' name='dn[cn]'>\n
    <input type='submit' name='addcrt' value='Add'>\n
  </fieldset>
";
}
if(@$_GET['v'] == 'log') {
$QLog = mysqli_query($db, "select `id`,`tsa-core`,`serialNumber`,`timeStamp`,`hostName`,`userAgent`,`headers`,`respStatus`,`request`,`response` from `".TSA_TABLELOGS."` order by `id` desc");
echo"<a href='.'>Home</a><br>

  <fieldset style='border:2px solid #3355aa; padding:2; background-color:#00dd00'>
  <legend><font size='4'>Client Logging</font></legend>
  <table id='AutoNumber1' style='FONT-SIZE: 9pt; BORDER-COLLAPSE: collapse' borderColor='#ffffff' cellSpacing='0' cellPadding='0' width='100%' border='1'>
<tr>";
$QFields = mysqli_query($db, "SHOW COLUMNS FROM `".TSA_TABLELOGS."`");
while($fields = mysqli_fetch_assoc($QFields)) {
  if($fields['Field'] != 'request') {
    if($fields['Field'] != 'response') {
      echo "<td>{$fields['Field']}</td>";
    }
  }
}
mysqli_free_result($QFields);
echo "<td>Request</td><td>Response</td></tr>";
while($fLog = mysqli_fetch_assoc($QLog)) {
  echo "<tr bgcolor='";
  if($fLog['tsa-core'] == '1') {
    echo "##afaea7";
  }
  echo "'>";
  foreach($fLog as $k=>$v) {
    if($k == 'request') {
      echo "  <td><a href='.'>Req (".strlen($v).") byte</a></td>\n";
    } elseif($k == 'response') {
      echo "  <td><a href='.'>Resp (".strlen($v).") byte</a></td>";
    } else {
      if($k == 'tsa-core') {
        if($v == '1') {
          echo"  <td>TSA1 (code signing)</td>\n";
        } else {
          echo"  <td>TSA0 (pdf signing)</td>\n";
        }
      } else {
        echo"  <td>".rtrim($v)."</td>\n";
      }
    }
  }
  echo "\n</tr>\n";
  //echo "<td><a href='.'>Request(".strlen($v).")</a></td><td><a href='.'>Response(".strlen($v).")</a></td></tr>";
}
echo"  </table>
  </fieldset>
";
mysqli_free_result($QLog);
}
?>
<script language='javascript'>
function hact() {
  var xmlhttp;
  if (window.XMLHttpRequest)  {
    // code for IE7+, Firefox, Chrome, Opera, Safari
    xmlhttp=new XMLHttpRequest();
    }
  else  {// code for IE6, IE5
    xmlhttp=new ActiveXObject("Microsoft.XMLHTTP");
    }
  xmlhttp.onreadystatechange=function()  {
    if (xmlhttp.readyState==4 && xmlhttp.status==200) {
        var stts =xmlhttp.getResponseHeader('status');
        //document.getElementById("hviewst").innerHTML=xmlhttp.responseText;
        //document.getElementById("tr_"+i).style.color = 'red';
        document.getElementById("topmsg").innerHTML = "<font color='green'><b>Success Updated, refreshing page...</b></font>";
        window.setTimeout("location.reload();", 2000);
        //alert('Success Updated');
      }
  }
  
  
<?php
foreach($tsaConfig as $tsaConfigSectionK=>$tsaConfigSectionV) {
  if($tsaConfigSectionK == 'database') {
    foreach(array_reverse($tsaConfigSectionV) as $k=>$v) {
      if($k != 'position') {
echo "var $k=document.getElementById(\"$k\").value;\n";
      }
    }
  }
  if($tsaConfigSectionK == 'common') {
    foreach(array_reverse($tsaConfigSectionV) as $k=>$v) {
      if($k != 'position') {
echo "var $k=document.getElementById(\"$k\").value;\n";
      }
    }
  }
}

echo "xmlhttp.open(\"GET\",\"cfg.php?act=updatecfg";
foreach($tsaConfig as $tsaConfigSectionK=>$tsaConfigSectionV) {
  if($tsaConfigSectionK == 'database') {
    foreach(array_reverse($tsaConfigSectionV) as $k=>$v) {
      if($k != 'position') {
echo "&$k=\"+$k+\"";
      }
    }
  }
  if($tsaConfigSectionK == 'common') {
    foreach(array_reverse($tsaConfigSectionV) as $k=>$v) {
      if($k != 'position') {
echo "&$k=\"+$k+\"";
      }
    }
  }
}
echo "\",true);\n";
?>
  xmlhttp.send();
}
//document.getElementById("tr_96").className = 'trred';
</script>

</body>
</html>