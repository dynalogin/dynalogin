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

function dynalogin_try_command($server, $port, $scheme, $use_tls, $command) {
    if($use_tls) {
        $sock = fsockopen("tls://".$server, $port, $errno, $errstr);
    } else {  
        $sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        socket_connect($sock, $server, $port);
    }

  // read greeting
  $greeting_code = dynalogin_read($sock);

  if($greeting_code == 220) {
    // send auth request
    socket_write($sock, $command."\n");

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

  socket_write($sock, "QUIT\n");
  socket_close($sock);
  return $logged_in;

}

function dynalogin_auth($user, $code, $server, $port, $scheme = "HOTP", $use_tls = false) {
    $request = "UDATA $scheme $user $code";
    return dynalogin_try_command($server, $port, $scheme, $use_tls, $request);
}

function dynalogin_auth_digest($user, $realm, $response, $digest_suffix,
    $server, $port, $scheme = "HOTP", $use_tls = false) {
    $request = "UDATA ".$scheme."-DIGEST $user $realm $response $digest_suffix";
    return dynalogin_try_command($server, $port, $scheme, $use_tls, $request);
}

?>
