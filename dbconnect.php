<?php
function dbconnect() {
  if($db = mysqli_connect(TSA_DBHOST, TSA_DBUSERNAME, TSA_DBPASSWORD)) {
    if(!mysqli_query($db, "use `".TSA_DBNAME."`")) {
      //return "Error: ".__CLASS__."::".__FUNCTION__." (".__FILE__.":".__LINE__."). Select Db error .MySQL say: ".mysqli_error($db);
      return mysqli_error($db);
    }
    return $db;
  } else {
    //return "Error: ".__CLASS__."::".__FUNCTION__." (".__FILE__.":".__LINE__."). mysql error connect to \"".TSA_DBHOST.":".TSA_DBPORT."\". MySQL say: ".mysqli_connect_error();
    return mysqli_connect_error();
  }
}
?>