# winvent

Intended to read the Windows Event log and send only selected event Id's to Cloudwatch. This is because there is no functionality in the CloudWatch Agent to filter this which means that every Windows Event is ingested so incurring un-necessary cost. 