### migrate-ssha

Reads a shadow file from stdin and outputs two files:

* `chpasswd.input` - a file containing a random password for each SSHA user that can be fed to the `chpaswd` command.
* `ssha-users.json` - a JSON file contianing the random password for each SSHA user, encrypted with their old password.
   
### decrypt-ssha.cgi
    
CGI program.  Reads the JSON file produced by `migrate-sha` in the location specified by the `$SSHA_USERS_FILE` environment variable.  Accepts HTTP requests with POST parameters `username` and `password` and attempts to decrypt the given user's random password with the supplied password.
