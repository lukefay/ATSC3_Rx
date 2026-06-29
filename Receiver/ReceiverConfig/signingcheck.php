<?php

/* 
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

header('Content-Type: text/event-stream');
// recommended to prevent caching of event data.
header('Cache-Control: no-cache'); 

if (substr(php_uname(), 0, 7) == "Windows") {
  $pyth="C:/Users/luke/AppData/Local/Programs/Python/Python38-32/python.exe";
} else {
  $pyth="/usr/bin/python";
}

chdir('../SLT_signalling');
$out = [];
$signingCode = 0;
//$command = escapeshellcmd("python signatureVerify.py 2>&1");

if (substr(php_uname(), 0, 7) == "Windows") {
  //pclose(popen("start \"bla\" \"" . $pyth . "\" " . escapeshellarg("signatureVerify.py"), "r"));
  //pclose(popen("start /B " . $pyth . " signatureVerify.py", "r"));
  //pclose(popen("start /B " . $pyth . " signatureVerify.py > NUL 2>&1", "r"));
  pclose(popen("start /B " . $pyth . " signatureVerify.py 2> signErr.bin", "r"));
  //pclose(popen("python signatureVerify.py", "r"));
  //$WshShell = new COM("WScript.Shell");
  //$oExec = $WshShell->Run("python signatureVerify.py", 0, false);
  //exec("python signatureVerify.py", $out, $signingCode);
  //exec($command, $out, $signingCode);
  //$out = shell_exec("python signatureVerify.py");
  //$signingCode = exec("python3 signatureVerify.py > /dev/null 2>&1 & echo $?");
  //system("python3 signatureVerify.py");
  //exec("echo %errorlevel%", $out, $signingCode);
  //$test = shell_exec("echo %errorlevel%");
  //shell_exec("python signatureVerify.py");
  //$signingCode = shell_exec("echo %errorlevel%");
  
  sleep(1);
  $signingCode = file_get_contents('./signErr.bin', FALSE, NULL, 0, 3);

} else {
  //exec("$pyth signatureVerify.py");
  //exec("sudo python ../SLT_signalling/signatureVerify.py");
  exec("python signatureVerify.py", $out, $signingCode);
  //exec("echo $?", $out, $signingCode);
}

chdir('../ReceiverConfig');

//echo $signingCode;
echo json_encode($signingCode);
//echo json_encode($out);
//echo json_encode($oExec);
?>
