# ATSC3_Rx
ATSC 3.0 receiver that uses ROUTE protocol to collect DASH segments from IP streams and render video on a browser that points to Apache 2.4 server containing recovered DASH segments. This is updated code that originally came from Thomas Stockhammer, available at https://github.com/haudiobe/ATSC_ROUTE. Architecture behind this code is described at that URL where Apache 2.4 server code runs the ROUTE protocol to collect files (e.g., DASH segments) and serve them to a browser. 

This code was tested with a variety of IP stream sources. Alignment of segment availability time from the source to Availability Start Time (AST) in the DASH manifest is a factor and line 44 of ProcessROUTE.php file ($Delay variable) can be used accordingly.  There is internal code to look for PTP time at UDP address 224.0.1.129:8000 but if not available it will use system time.

Codec availability depends on browser choice and codec choice from the sender.  A list of codec support can be found at https://caniuse.com.  (https://caniuse.com/?search=hevc) Specific codec versions (e.g., Main vs. Main10) can be checked in the browser console as 
> MediaSource.isTypeSupported('video/mp4; codecs=hvc1.2.4.L123')

> MediaSource.isTypeSupported('audio/mp4; codecs=ac-4.02.01.00')

This code includes Python and PHP scripts. Paths either assume direct access to executable directories or that the environment path has included those paths. Python executable is typically installed under a User AppData directory. Python exectuable absolute paths need to be set in the following files.

Receiver/ProcessROUTE.php

Receiver/updateTime.php

Receiver/ReceiverConfig/onloadfunc.php

Receiver/ReceiverConfig/updateTime.php

For ATSC3 in North America, be aware that Dolby AC-4 codecs are not available in any browser and HEVC was only tested on Chrome browser on a later model PC (assuming the platform has appropriate hardware to support that codec).  Also note that IMSC1 captions decoding also requires a decoder codec available to the browser.
