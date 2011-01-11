<?php



function dynalogin_read($sock) {
  if(!socket_last_error($sock)) {
    while($line = socket_read($sock, 512, PHP_NORMAL_READ)) {
#      echo "<p>".$line."</p>";
      if(!preg_match("/^(\d\d\d)([- ])(.*)\$/", $line, $elements)) {
        echo "bad data line\n";
        return FALSE;
      }
      $code = $elements[1];
      $last_line = ($elements[2] == " ");
      $msg = $elements[3];
      if($last_line) {
        return $code;
      }
    }
  }
  return FALSE;
}

function dynalogin_auth($user, $realm, $response, $digest_suffix,
    $server, $port) {

  $sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
  socket_connect($sock, $server, $port);

  // read greeting
  $greeting_code = dynalogin_read($sock);
  
  if($greeting_code == 220) {
    // send auth request
    $request = "UDATA HOTP-DIGEST $user $realm $response $digest_suffix\n";
    socket_write($sock, $request);

    // check response
    $response_code = dynalogin_read($sock);
    if($response_code == 250)
      $logged_in = 1;
    else
      $logged_in = 0;
  } else {
    // bad greeting
    echo "bad greeting";
  }

  // quit
//  socket_close($sock);
  return $logged_in;
}

?>
