# SophosUTMPostPatch
Leverages PoshAcme and Sophos API


I leverage Posh-Acme for the Cert issue portion. Send them love as they made the cert issue part super easy
https://github.com/rmbolger/Posh-ACME

This script will check if you have a copy of the cert uploaded. If you dont it will make a new 509 object and then post a new cert object

if there is already a copy that needs to be updated it will patch the 509 object and then patch over the old cert. so that any reference to the orignal cert will be updated
