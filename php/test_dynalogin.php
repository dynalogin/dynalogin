<?PHP

include "dynalogin.php";

$my_user = "testuser";
$my_scheme = "HOTP";
$my_host = "localhost";
$my_port = 9050;
$my_result = "";

if (isset($_POST['user'])) {
  $my_host = $_POST['host'];
  $my_port = $_POST['port'];
  $my_user = $_POST['user'];
  $my_scheme = $_POST['scheme'];
  $my_code = $_POST['code'];

  if(dynalogin_auth($my_user, $my_code,
     $my_host, $my_port, $my_scheme,
     true)) {
    $my_result = "success";
  } else {
    $my_result = "fail";
  }
  
}

?>
<html>
  <head><title>dynalogin test</title></head>

  <body>
  <p>Previous result: <? echo $my_result; ?></p>
  <form method="post">
    <p>Host (TLS): <input type="text" name="host" value="<?echo $my_host;?>"/></p>
    <p>Port: <input type="text" name="port" value="<?echo $my_port;?>"/></p>
    <p>Username: <input type="text" name="user" value="<?echo $my_user;?>"/></p>
    <p>Scheme (HOTP or TOTP): <input type="text" name="scheme" value="<?echo $my_scheme;?>"/></p>
    <p>Code (displayed in cleartext!): <input type="text" name="code" value=""/></p>
    <p><input type="submit" value="Submit"/></p>
  </form>
</html>
