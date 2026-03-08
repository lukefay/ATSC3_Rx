# ATSC3_Rx
ATSC 3.0 receiver that uses ROUTE protocol to collect DASH segments from IP streams and render video on a browser that points to Apache 2.4 server containing recovered DASH segments. This is updated code that originally came from Thomas Stockhammer, available at https://github.com/haudiobe/ATSC_ROUTE. Architecture behind this code is described at that URL where Apache 2.4 server code runs the ROUTE protocol to collect files (e.g., DASH segments) and serve them to a browser. 
Codec availability depends on browser choice and codec choice from the sender.  A list of codec support can be found at https://caniuse.com.  (https://caniuse.com/?search=hevc) Specific codec versions (e.g., Main vs. Main10) can be checked in the browswer console as 
> MediaSource.isTypeSupported('video/mp4; codecs=hvc1.2.4.L123')
> MediaSource.isTypeSupported('audio/mp4; codecs=ac-4.02.01.00')

This code includes Python and PHP scripts. Paths either assume direct access to executable directories or that the environment path has included those paths. 
For ATSC3, Dolby AC-4 codecs are not available in any browser and HEVC is only available on Chrome browsers (assuming the platform has appropriate hardware to support that codec). 
