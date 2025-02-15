# winvent

Intended to read the Windows Event log and send only selected event Id's to Cloudwatch. This is because there is no functionality in the CloudWatch Agent to filter this which means that every Windows Event is ingested so incurring un-necessary cost. 

## things to do

* add debug file path option
  * sort out permissions of debug file if needed
  * maybe add a -debug filepath option to the installer as well
* add tests to create (local) events and check it's working possibly
  * at the very least document how to do this using PowerShell
* add filter by event ID back in
* add 'send to cloudwatch' functionality
* add install flags to specify event id's at install time e.g. ./winvent.exe 1002 7604 install (or however this is done)
* split up code properly into 'service', cloudwatch and event polling