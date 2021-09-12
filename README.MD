# IEEE-Deploy

This is a basic Flask webserver to auto-deploy changes to some Purdue IEEE web services.

The way it works is by recieving a webhook from GitHub for certain repositories and then doing a `git pull` on the corresponding repo.

## Updating this service
When you are ready to roll out a new version of this service, you will NEED to remove the `deploy/__init__.pyc` and `deploy/secrets.pyc` cache files and perform an Apache restart. Apache will cache the WSGI configuration and old code. 

If you want to add/remove/update the repos this works for, change the file mapping table and perform the above steps.

## Logs
A rotating log is stored in `/var/log/IEEE-Deploy/`. It will cap each file to 100 KiB and keep only 3 past logs. Since this should be called pretty infrequently, the logs should stay pretty manageable.