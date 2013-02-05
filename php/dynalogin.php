<?php



function dynalogin_read($fp) {
    if(!feof($fp)) {
        while($line = fgets($fp, 512)) {
#        echo "<p>".$line."</p>";
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

function dynalogin_write($fp, $msg) {
    fwrite($fp, $msg);
}

function dynalogin_try_command($server, $port, $use_tls, $command) {
    if($use_tls) {
        $fp = stream_socket_client("tls://".$server.':'.$port, $errno, $errstr);
    } else {  
        $fp = stream_socket_client("tcp://".$server.':'.$port, $errno, $errstr);
    }
    if(!$fp)
        return 0;

    // read greeting
    $greeting_code = dynalogin_read($fp);

    if($greeting_code == 220) {
    // send auth request
    dynalogin_write($fp, $command."\n");

    // check response
    $response_code = dynalogin_read($fp);
    if($response_code == 250)
        $logged_in = 1;
    else
        $logged_in = 0;
    } else {
        // bad greeting
        syslog(LOG_ERR, "dynalogin: bad greeting");
    }

    dynalogin_write($fp, "QUIT\n");
    fclose($fp);

    if($logged_in == 0)
        syslog(LOG_WARNING, "dynalogin: login failure"); 
    return $logged_in;
}

function dynalogin_auth($user, $code, $server, $port, $scheme = "HOTP", $use_tls = false) {
    $request = "UDATA $scheme $user $code";
    return dynalogin_try_command($server, $port, $use_tls, $request);
}

function dynalogin_auth_digest($user, $realm, $response, $digest_suffix,
    $server, $port, $scheme = "HOTP", $use_tls = false) {
    $request = "UDATA ".$scheme."-DIGEST $user $realm $response $digest_suffix";
    return dynalogin_try_command($server, $port, $use_tls, $request);
}

?>
