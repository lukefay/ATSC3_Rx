<?php

/* 
Clean up processes
 */
if (substr(php_uname(), 0, 7) == "Windows") {
  exec("taskkill /F /IM flute.exe /T");
} else {
  exec("sudo killall flute -w" . " > /dev/null &");
}

?>