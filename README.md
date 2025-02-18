# winvent

Intended to read the Windows Event log and send only selected event Id's to Cloudwatch. This is because there is no functionality in the CloudWatch Agent to filter this which means that every Windows Event is ingested so incurring un-necessary cost. 

## Config

See config.toml file example

## Installation

./winvent.exe install

This will create a config.toml file in the same directory as the executable including the defaults. TODO: change this to be called example_config.toml when installed and if config.toml exists use that instead. This aids in setting up automation.

TODO: Change service start type to Automatic rather than manual. 

## Running 

Start-Service WindowsEventLogger TODO: consider changing the name. 

If you change the config 'cause you've added more EventId's or want to look at a different logging namespace then run Restart-Service WindowsEventLogger and it will run with the new config

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