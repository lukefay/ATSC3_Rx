<?php

/* 
Main script for starting ROUTE reception
 */
header('Content-Type: text/event-stream');
# recommended to prevent caching of event data.
header('Cache-Control: no-cache'); 
 
$micro_date = microtime();
$date_array = explode(" ",$micro_date);
$date = date("Y-m-d H:i:s",$date_array[1]);
unlink ('../bin/timelog.txt');
file_put_contents ( "timelog.txt" , "Start:" . $date . $date_array[0] . " \r\n" , FILE_APPEND );

ini_set('memory_limit','-1');//remove memory limit

/* 
Main script for starting flute reception and MPD re-writing
 */
$AdSource = intval(file_get_contents("RcvConfig.txt"));
chdir('../bin/');
$currDir=dirname(__FILE__);

$channel = $_REQUEST['channel'];
$responseToSend = array();
$responseToSend[0] = $channel;
#echo "Started channel ". $channel;

#Define Paths
$DASHContentBase="DASH_Content";
$DASHContentDir=$DASHContentBase . (string)$channel;
if (substr(php_uname(), 0, 7) == "Windows") {
  $DASHContent=$currDir . "\\" . $DASHContentDir;
} else {
  $DASHContent="/var/www/html/Route_Receiver/Receiver/" . $DASHContentDir;
}

# Define Variables
#$OriginalMPD= "MultiRate_Dynamic.mpd";
$OriginalMPD= "ManifestUpdate_Dynamic.mpd";
$AdMPDName="Ad2/Ad2_MultiRate.mpd";

$PatchedMPD="MultiRate_Dynamic_Patched.mpd";
if (substr(php_uname(), 0, 7) == "Windows") {
  #$FLUTEReceiver=realpath("../route/Debug");
  $FLUTEReceiver=realpath("../route/Release");
} else {
  $FLUTEReceiver="/var/www/html/Route_Receiver/bin";
}
#HTMLLocalStorage="/home/nomor/.config/google-chrome-unstable/Default/Local Storage/"


$Log="Rcv_Log_MPD" . (string)$channel . ".txt";		#Log containing delays corresponding to FLUTE receiver
$encodingSymbolsPerPacket=0;	#For Receiver, Only a value of zero makes a difference. Otherwise, it is ignored 
							#This means that more than one encoding symbol is included packet. This could be varying

#Clear HTML5 Local Storage
#if [ -e "$HTMLLocalStorage"*${Client:7}*localstorage-journal -o -e "$HTMLLocalStorage"*${Client:7}*localstorage ]; then
#  echo "Delete Old HTML Local Storage"
#  rm "$HTMLLocalStorage"*${Client:7}*
#fi

#Initialize DASHContent Folder
exec("mkdir $DASHContent");
if (substr(php_uname(), 0, 7) == "Windows") {
  array_map('unlink', glob("$DASHContent\\*"));
} else {
  array_map('unlink', glob("$DASHContent/*"));
}

#Start ROUTE Protocol operation by reading LLS @ 224.0.23.60:4937
chdir('../Receiver/SLT_signalling');
if (substr(php_uname(), 0, 7) == "Windows") {
  #$pyth="C:/Users/luke/AppData/Local/Programs/Python/Python38-32/python.exe";
  $pyth="C:/Users/luke/AppData/Local/Programs/Python/Python313/python.exe";
} else {
  $pyth="/usr/bin/python";
}
$result = json_decode(shell_exec("$pyth readFromSLT.py " . $channel), true);
$destIP=$result[0];
$sourceIP=$result[1];
$port=$result[2];
$serviceName=$result[3];
$majorCH=$result[4];
$minorCH=$result[5];

# Read PTP time from the PHY
#json_decode(shell_exec("$pyth time.py"), true);
$PTP = floatval(file_get_contents("PTP_TIME.dat"));
if (!$PTP) die("Failed loading PTP time");


# Read UTC offset from PTP time with LLS table 0x03 (SystemTime)
$ST = simplexml_load_file("SystemTime.xml");
if (!$ST) die("Failed loading XML file");

#$ST_UTC = intval($ST->SystemTime[0]['currentUtcOffset']);
$ST_UTC = intval($ST['currentUtcOffset']);

chdir('../../bin');
file_put_contents ( "timelog.txt" , "Channel: " . $channel . " \r\n" , FILE_APPEND );
file_put_contents ( "timelog.txt" , "PTP time:" . $PTP . " \r\n" , FILE_APPEND );
file_put_contents ( "timelog.txt" , "Loaded UTC offset:" . $ST_UTC . " \r\n" , FILE_APPEND );
file_put_contents ( "timelog.txt" , "Read from SLT:" . $destIP . " " . $sourceIP . " " . $port . " " . $serviceName . " " . $majorCH . "." . $minorCH . " \r\n" , FILE_APPEND );

$micro_date = microtime();
$start_array = explode(" ",$micro_date);
$start = date("Y-m-d H:i:s",$start_array[1]);
file_put_contents ( "timelog.txt" , "Launching ROUTE:" . $start . $start_array[0] . " \r\n" , FILE_APPEND );

# Start ROUTE receiver
if (substr(php_uname(), 0, 7) == "Windows") {
  $cmd="$FLUTEReceiver/flute.exe -A -B:$DASHContent -m:$destIP -p:$port -t:0 -E -b:1 -Y:$encodingSymbolsPerPacket -v:0";
  #$cmd="$FLUTEReceiver/flute.exe -A -B:$DASHContent -m:$destIP -p:$port -t:0 -E -b:1 -Y:$encodingSymbolsPerPacket -v:0 -J:$Log &";
  #$cmd="$FLUTEReceiver/flute.exe -A -B:$DASHContent -m:$destIP -p:$port -t:0 -E -b:0 -Y:$encodingSymbolsPerPacket -v:4 -J:$Log > logout0.txt &";  #Large memory 
} else {
  $cmd="$FLUTEReceiver/flute -A -B:$DASHContent -m:$destIP -p:$port -t:0 -E -b:1 -Y:$encodingSymbolsPerPacket -v:0";
}
if (substr(php_uname(), 0, 7) == "Windows") {
  pclose(popen("start /B ". $cmd, "r"));
} else {
  exec($cmd . " > /dev/null &");
  #$ret=exec($cmd . " > /dev/null &", $out, $err);
  #var_dump($ret);
  #var_dump($out);
  #var_dump($err);
}

$micro_date = microtime();
$date_array = explode(" ",$micro_date);
$date = date("Y-m-d H:i:s",$date_array[1]);
file_put_contents ( "timelog.txt" , "Start SLS:" . $date . $date_array[0] . " \r\n" , FILE_APPEND );

# Allow processing time to capture SLS / Get files through virus checkers
if (substr(php_uname(), 0, 7) == "Windows") {
  while (!glob($DASHContent."\\"."sls")) usleep(1000);	// wait to collect SLS file
} else {
  while (!glob($DASHContent."/"."sls")) usleep(1000);
}

#Read the content from the envelope file to find contents of SLS
if (substr(php_uname(), 0, 7) == "Windows") {
  file_put_contents ( "timelog.txt" , "Read Envelope:" . $DASHContent . "\\envelope.xml" . "\r\n" , FILE_APPEND );
} else {
  file_put_contents ( "timelog.txt" , "Read Envelope:" . $DASHContent . "/envelope.xml" . "\r\n" , FILE_APPEND );
}
if (substr(php_uname(), 0, 7) == "Windows") {
  $metadataEnvelope = simplexml_load_file("$DASHContent" . "\\" . "envelope.xml");
} else {
  $metadataEnvelope = simplexml_load_file("$DASHContent" . "/envelope.xml");
}
if (!$metadataEnvelope) die("Failed loading Envelope XML file");
$items = count($metadataEnvelope->item);
for ($i = 0; $i < $items; $i++) {
  $test = $metadataEnvelope->item[$i]['contentType'];
  if ($test == "application/route-usd+xml") { $USBDUri = $metadataEnvelope->item[$i]['metadataURI']; }
  else if ($test == "application/route-s-tsid+xml") { $sTSIDUri = $metadataEnvelope->item[$i]['metadataURI']; }
  else if ($test == "application/dash+xml") { $MPDUri = $metadataEnvelope->item[$i]['metadataURI']; }
  else if ($test == "application/atsc-held+xml") { $HELDUri = $metadataEnvelope->item[$i]['metadataURI']; }
}
#file_put_contents ( "timelog.txt" , "USBD filename '" . $USBDUri . "' S-TSID filename '" . $sTSIDUri . "' MPD filename '" . $MPDUri . "' HELD filename '" . $HELDUri . "' \r\n" , FILE_APPEND );
file_put_contents ( "timelog.txt" , "USBD filename '" . $USBDUri . "' S-TSID filename '" . $sTSIDUri . "' MPD filename '" . $MPDUri . "' \r\n" , FILE_APPEND );

# Read the contents of the USBD file
if (substr(php_uname(), 0, 7) == "Windows") {
  //while (!glob($DASHContent."\\".$USBDUri)) usleep(1000);	// Wait to collect the file
} else {
  //while (!glob($DASHContent."/".$USBDUri)) usleep(1000);
}
if (substr(php_uname(), 0, 7) == "Windows") {
  $BundleDescriptionROUTE = simplexml_load_file("$DASHContent" . "\\" . $USBDUri);
} else {
  $BundleDescriptionROUTE = simplexml_load_file("$DASHContent" . "/" . $USBDUri);
}
if (!$BundleDescriptionROUTE) die("Failed loading USBD file");
$bases = count($BundleDescriptionROUTE->UserServiceDescription[0]->DeliveryMethod->BroadcastAppService->BasePattern);
for ($i = 0; $i < $bases; $i++) {
  $Base[$i] = $BundleDescriptionROUTE->UserServiceDescription[0]->DeliveryMethod->BroadcastAppService->BasePattern[$i];
  $segTemplate[$i] = $Base[$i] . "*.m*";
}
file_put_contents ( "timelog.txt" , "MPD: " . $MPDUri . " \r\n" , FILE_APPEND );
file_put_contents ( "timelog.txt" , "S-TSID: " . $sTSIDUri . " \r\n" , FILE_APPEND );
file_put_contents ( "timelog.txt" , "BaseURL: " . $Base[0] . " \r\n" , FILE_APPEND );

$micro_date = microtime();
$date_array = explode(" ",$micro_date);
$date = date("Y-m-d H:i:s",$date_array[1]);
file_put_contents ( "timelog.txt" , "Start reading MPD:" . $date . $date_array[0] . " \r\n" , FILE_APPEND );
if (substr(php_uname(), 0, 7) == "Windows") {
  //while (!glob($DASHContent."\\".$MPDUri)) usleep(1000);	// Wait to collect the file
} else {
  //while (!glob($DASHContent."/".$MPDUri)) usleep(1000);
}

# Allow processing time to capture Segments
if (substr(php_uname(), 0, 7) == "Windows") {
  //while (!glob($DASHContent."\\".$init)) usleep(1000);	// wait to collect the file
  while (count(glob($DASHContent."\\".$segTemplate[1])) < 2) usleep(1000);	// Wait to collect more than 2 segment
} else {
  //while (!glob($DASHContent."/".$init)) usleep(1000);	// wait to collect the file
  while (count(glob($DASHContent."/".$segTemplate[1])) < 2) usleep(1000);	// Wait to collect more than 2 segment
}

if (substr(php_uname(), 0, 7) == "Windows") {
  $MPD = simplexml_load_file("$DASHContent" . "\\" . $MPDUri);
} else {
  $MPD = simplexml_load_file("$DASHContent" . "/" . $MPDUri);
}
if (!$MPD) die("Failed loading XML file");

$micro_date = microtime();
$date_array = explode(" ",$micro_date);
$date_array[0] = round($date_array[0],4);
$date = date("Y-m-d H:i:s",$date_array[1]);
file_put_contents ( "timelog.txt" , "Tuned in:" . $date . $date_array[0] . " \r\n" , FILE_APPEND );

$Delay = $date_array[1] - $start_array[1];	#How much would the AST of the patched MPD be lagging the current system time, i.e. how far in future is the AST (in seconds)?
$Delay += $date_array[0] - $start_array[0];
file_put_contents ( "timelog.txt" , "Delay: " . $Delay . " \r\n" , FILE_APPEND );

$dom_sxe = dom_import_simplexml($MPD);
if (!$dom_sxe) {
	echo 'Error while converting XML';
	exit;
}

$dom = new DOMDocument('1.0');
$dom_sxe = $dom->importNode($dom_sxe, true);
$dom_sxe = $dom->appendChild($dom_sxe);

$periods = parseMPD($dom->documentElement);

$cumulativeUpdatedDuration = 0;    //Cumulation of period duration on updated MPD
$tuneInPeriodStart = 0;

$MPDNode = &$periods[0]['node']->parentNode;

$AST_BCST = $PTP - $ST_UTC - $Delay;
file_put_contents ( "timelog.txt" , "Broadcast AST: " . $AST_BCST . "\r\n" , FILE_APPEND );

$AST_SEC = new DateTime( 'now',  new DateTimeZone( 'UTC' ) );	/* initializer for availability start time */
$AST_SEC->setTimestamp($date_array[1]);    //Better use a single time than now above
#$AST_SEC->add(new DateInterval('PT1S'));
$AST_SEC_W3C = $AST_SEC->format(DATE_W3C);

preg_match('/\.\d*/',$date_array[0],$dateFracPart);
$extension_pos = strrpos($AST_SEC_W3C, '+'); // find position of the last + in W3C date to slip frac seconds
$AST_W3C = substr($AST_SEC_W3C, 0, $extension_pos) . $dateFracPart[0] . "Z" ; //substr($AST_SEC_W3C, $extension_pos);
file_put_contents ( "timelog.txt" , "Setting AST: " . $AST_W3C . " \r\n" , FILE_APPEND );

#For using with the canned trace file, re-write the AST to current system time when MPD is received
$MPD_AST = $MPDNode->getAttribute("availabilityStartTime");
preg_match('/\.\d*/',$MPD_AST,$matches);
$fracAST = "0" . $matches[0];
$originalAST = new DateTime($MPD_AST);     
#$deltaTimeASTTuneIn = $AST_SEC->getTimestamp() + round($date_array[0],4) - ($originalAST->getTimestamp() + $fracAST);  //Time elapsed between the original AST and Tune-in time
$deltaTimeASTTuneIn = $AST_SEC->getTimestamp() - $AST_BCST;  //Time elapsed between the original PHY time and Tune-in time


#file_put_contents ( "timelog.txt" , "TimeOffset: " . $deltaTimeASTTuneIn . ", Original time:" . ($originalAST->getTimestamp() + $fracAST) . " Tune-in time: " . ($AST_SEC->getTimestamp() + round($date_array[0],4)) . "\r\n" , FILE_APPEND );
file_put_contents ( "timelog.txt" , "TimeOffset: " . $deltaTimeASTTuneIn . ", Original time:" . ($originalAST->getTimestamp()) . " Updated time: " . ($originalAST->getTimestamp() + $deltaTimeASTTuneIn) . "\r\n" , FILE_APPEND );

$ASTNew = date("Y-m-d H:i:s", ($originalAST->getTimestamp() + $Delay/4)) . "Z";
#$ASTNew = date("Y-m-d H:i:s", ($originalAST->getTimestamp() - $deltaTimeASTTuneIn)) . "Z";
#$ASTNew = date("Y-m-d H:i:s", ($originalAST->getTimestamp() + $deltaTimeASTTuneIn/4)) . "Z";
#$MPDNode->setAttribute("availabilityStartTime",date("Y-m-d H:i:s", ($originalAST->getTimestamp() + $deltaTimeASTTuneIn)) . "Z");    //Set AST to tune-in time
$MPDNode->setAttribute("availabilityStartTime",str_replace(" ", "T", $ASTNew));    //Set AST to tune-in time
$MPDNode->setAttribute("minBufferTime",str_replace(" ", "T", "PT0S"));    // Remove minBufferTime

$periodStart;   //Start of this period in the iteration
$duration;      //Duration of current period in the iteration
$lastPeriodStart;   //Period start of the last period in the iteration
$lastPeriodDuration;    //Period duration of the last period in iteration

$responseToSend[1] = count($periods) - 1;

for ($periodIndex = 0; $periodIndex < count($periods); $periodIndex++) {
	//Loop on all periods in orginal MPD
	$periodStart = $periods[$periodIndex]['node']->getAttribute("start");
	$duration = $periods[$periodIndex]['node']->getAttribute("duration");
	#$duration = somehowPleaseGetDurationInFractionalSecondsBecuasePHPHasABug($periods[$periodIndex]['node']->getAttribute("duration"));
	
	if($periodStart === '') $periodStart = $lastPeriodStart + $lastPeriodDuration;
	else $periodStart = somehowPleaseGetDurationInFractionalSecondsBecuasePHPHasABug($periodStart);	//Convert Duration string to number
	if($duration === '') $duration = 60;
	file_put_contents ( "timelog.txt" , "START TIME: " . $periodStart . "\tDelta: " . $deltaTimeASTTuneIn . "\r\n" , FILE_APPEND );
	
	if($deltaTimeASTTuneIn < $periodStart) {
		//Tune-in is before this period, it stays intact (except that its start may need an update, which is optional for subsequent periods)
		$periods[$periodIndex]['node']->setAttribute("start","PT". round($lastPeriodStart + $lastPeriodDuration,4)."S"); 
		//Set already for the next iteration
		$lastPeriodStart = $lastPeriodStart + $lastPeriodDuration;
		$responseToSend[1] = $lastPeriodStart;
		$lastPeriodDuration = $duration;
		file_put_contents ( "timelog.txt" , "EARLY PERIOD: " . $deltaTimeASTTuneIn . "\r\n" , FILE_APPEND );
		continue;
	}
	
	//Set already for the next iteration
	$lastPeriodStart = $periodStart;
	$lastPeriodDuration = $duration;  
	
	if($deltaTimeASTTuneIn > $periodStart + $duration) {
		//This period is no more relevant and is not received, hence remove this
		$dom->documentElement->removeChild ($periods[$periodIndex]['node']);
		$responseToSend[1] = $responseToSend[1] - 1;
		file_put_contents ( "timelog.txt" , "LATE PERIOD: " . $deltaTimeASTTuneIn . "\r\n" , FILE_APPEND );
		continue;
	}

	//The only case here is the period in which we tune in
	
	$videoRep = &$periods[$periodIndex]['adaptationSet'][0]['representation'][0];
	$videoCodec = $videoRep['node']->getAttribute("codecs");
	$audioRep = &$periods[$periodIndex]['adaptationSet'][1]['representation'][0];
	$audioCodec = $audioRep['node']->getAttribute("codecs");
	file_put_contents ( "timelog.txt" , "Video Codec " . $videoCodec . "\r\n" , FILE_APPEND );
	file_put_contents ( "timelog.txt" , "Audio Codec " . $audioCodec . "\r\n" , FILE_APPEND );
	
	//$videoSegmentTemplate = &$periods[$periodIndex]['adaptationSet'][0]['representation'][0]['segmentTemplate'][0];
	$videoSegmentTemplate = &$periods[$periodIndex]['adaptationSet'][0]['segmentTemplate'][0];	
	$videoTimescale = $videoSegmentTemplate['node']->getAttribute("timescale");
	$videoSegmentDuration = $videoSegmentTemplate['node']->getAttribute("duration");
	$videoStartNum = $videoSegmentTemplate['node']->getAttribute("startNumber");
	$videoPTO = (int)$videoSegmentTemplate['node']->getAttribute("presentationTimeOffset");
	file_put_contents ( "timelog.txt" , "VIDEO TIMESCALE: " . $videoTimescale . "\tVIDEO DURATION: " . $videoSegmentDuration . "\r\n" , FILE_APPEND );
	
	$newVideoStartNumber = ceil(($deltaTimeASTTuneIn - $periodStart)*$videoTimescale/$videoSegmentDuration) + $videoStartNum;
	file_put_contents ( "timelog.txt" , "new video offset: " . ($deltaTimeASTTuneIn - $periodStart)*$videoTimescale/$videoSegmentDuration . "\r\n" , FILE_APPEND );
	$videoOffsetUpdate = ($newVideoStartNumber - $videoStartNum) * $videoSegmentDuration/$videoTimescale;
		
	//$audioSegmentTemplate = &$periods[$periodIndex]['adaptationSet'][1]['representation'][0]['segmentTemplate'][0];
	$audioSegmentTemplate = &$periods[$periodIndex]['adaptationSet'][1]['segmentTemplate'][0];
	
	$audioTimescale = $audioSegmentTemplate['node']->getAttribute("timescale");
	$audioSegmentDuration = $audioSegmentTemplate['node']->getAttribute("duration");
	$audioStartNum = $audioSegmentTemplate['node']->getAttribute("startNumber");
	$audioPTO = (int)$audioSegmentTemplate['node']->getAttribute("presentationTimeOffset");
	file_put_contents ( "timelog.txt" , "AUDIO TIMESCALE: " . $audioTimescale . "\tAUDIO DURATION: " . $audioSegmentDuration . "\r\n" , FILE_APPEND );
	
	$newAudioStartNumber = ceil(($deltaTimeASTTuneIn - $periodStart)*$audioTimescale/$audioSegmentDuration) + $audioStartNum;
	file_put_contents ( "timelog.txt" , "new audio offset: " . ($deltaTimeASTTuneIn - $periodStart)*$audioTimescale/$audioSegmentDuration . "\r\n" , FILE_APPEND );
	$audioOffsetUpdate = ($newAudioStartNumber - $audioStartNum) * $audioSegmentDuration/$audioTimescale;
	
	// Find the smaller update offset of audio and video, set the other to the smaller
	$offsetUpdate = min($videoOffsetUpdate , $audioOffsetUpdate);
	
	$newAudioPTO = round($offsetUpdate*$audioTimescale + $audioPTO); //Round, since PTO is int type
	$newVideoPTO = round($offsetUpdate*$videoTimescale + $videoPTO); //Round, since PTO is int type
	
	//The adjusted period start and duration governed by new audio/video offset above.
	//$periods[$periodIndex]['node']->setAttribute("start","PT". round($offsetUpdate + $periodStart - $deltaTimeASTTuneIn ,4)."S");         
	
	//$remainingPeriodDuration = $duration - max($videoOffsetUpdate , $audioOffsetUpdate);
	
	//$periods[$periodIndex]['node']->setAttribute("duration", "PT". round($remainingPeriodDuration,4) . "S");
	
	//Update again the last saved values for the next iteration
	$lastPeriodStart = $offsetUpdate + $periodStart - $deltaTimeASTTuneIn;
	$lastPeriodDuration = $remainingPeriodDuration;   
	
	//$videoSegmentTemplate->setAttribute("presentationTimeOffset",$newVideoPTO);
	//$videoSegmentTemplate->setAttribute("startNumber",$newVideoStartNumber);
	
	//$audioSegmentTemplate->setAttribute("presentationTimeOffset",$newAudioPTO);
	//$audioSegmentTemplate->setAttribute("startNumber",$newAudioStartNumber);
	
	//$periods[$periodIndex]['node']->removeChild ($periods[$periodIndex]['adaptationSet'][1]['node']);
}

if (substr(php_uname(), 0, 7) == "Windows") {
  $dom->save($DASHContent . "\\" . $PatchedMPD);
} else {
  $dom->save($DASHContent . "/" . $PatchedMPD);
}

file_put_contents ( "timelog.txt" , "responseToSend Channel: " . $responseToSend[0] . " Period count: " . $responseToSend[1] . "\r\n", FILE_APPEND );

echo json_encode($responseToSend);
echo $PatchedMPD;
#file_put_contents ( "timelog.txt" , $latestFiles , FILE_APPEND );
$micro_date = microtime();
$date_array = explode(" ",$micro_date);
$date = date("Y-m-d H:i:s",$date_array[1]);
file_put_contents ( "timelog.txt" , "Done:" . $date . $date_array[0] . " \r\n" , FILE_APPEND );


function &parseMPD($docElement) {
	foreach ($docElement->childNodes as $node) {
		//echo $node->nodeName; // body
		if($node->nodeName === 'Location') $locationNode = $node;
		if($node->nodeName === 'BaseURL') $baseURLNode = $node;    
		if($node->nodeName === 'Period') {
			$periods[]['node'] = $node;
			
			$currentPeriod = &$periods[count($periods) - 1];
			foreach ($currentPeriod['node']->childNodes as $node) {
				if($node->nodeName === 'AdaptationSet') {
					$currentPeriod['adaptationSet'][]['node'] = $node;
					
					$currentAdaptationSet = &$currentPeriod['adaptationSet'][count($currentPeriod['adaptationSet']) - 1];                    
					foreach ($currentAdaptationSet['node']->childNodes as $node) {
						if($node->nodeName === 'Representation') {
							$currentAdaptationSet['representation'][]['node'] = $node;
							
							$currentRepresentation = &$currentAdaptationSet['representation'][count($currentAdaptationSet['representation']) - 1];
							
							foreach ($currentRepresentation['node']->childNodes as $node) {
								if($node->nodeName === 'SegmentTemplate') $currentRepresentation['segmentTemplate']['node'] = $node;
								if($node->nodeName === 'AudioChannelConfiguration') $currentRepresentation['audioChannelConfiguration']['node'] = $node;
							}
						}
						if($node->nodeName === 'SegmentTemplate') {
							$currentAdaptationSet['segmentTemplate'][]['node'] = $node;
							
							$currentSegmentTemplate = &$currentAdaptationSet['segmentTemplate'][count($currentAdaptationSet['segmentTemplate']) - 1];
							
						}
						if($node->nodeName === 'SupplementalProperty') {
							$currentAdaptationSet['supplementalProperty'][]['node'] = $node;
							
							$currentSupplementalProperty = &$currentAdaptationSet['supplementalProperty'][count($currentAdaptationSet['supplementalProperty']) - 1];
							
						}
						if($node->nodeName === 'Accessibility') {
							$currentAdaptationSet['accessibility'][]['node'] = $node;
							
							$currentAccessibility = &$currentAdaptationSet['accessibility'][count($currentAdaptationSet['accessibility']) - 1];
							
						}
						if($node->nodeName === 'RandomAccess') {
							$currentAdaptationSet['randomAccess'][]['node'] = $node;
							
							$currentRandomAccess = &$currentAdaptationSet['randomAccess'][count($currentAdaptationSet['randomAccess']) - 1];
							
						}
						if($node->nodeName === 'Role') {
							$currentAdaptationSet['role'][]['node'] = $node;
							
							$currentRole = &$currentAdaptationSet['role'][count($currentAdaptationSet['role']) - 1];
							
						}
					}
				}
			}
		}
	}
	
	return $periods;
}

function somehowPleaseGetDurationInFractionalSecondsBecuasePHPHasABug($durstr) {
	if(strpos($durstr,'.') !== FALSE) {
		//If indeed there is float values
		$temp = explode('.', $durstr);
		$durstrint = $temp[0] . 'S';
		$temp1 = explode('.', $durstr);
		$temp2 = explode('S',$temp1[1]);
		$fracSec = '0.' . $temp2[0];
	}
	else {
		$durstrint = $durstr;
		$fracSec = 0;
	}
	
	$di = new DateInterval($durstrint);
	
	$durationDT = new DateTime();
	$reft = clone $durationDT;
	$durationDT->add($di);
	$duration = $durationDT->getTimestamp() - $reft->getTimestamp() + $fracSec;
	
	return $duration;
}
?>