### migrate-ssha

Reads a shadow file from stdin and produces two files:

* `chpasswd.input` - a file containing a random password for each SSHA user that can be fed to the `chpaswd` command.
* `ssha-users.json` - a JSON file containing the random password for each SSHA user, encrypted with their old password.
   
### decrypt-ssha.cgi
    
CGI program.  Reads the JSON file produced by `migrate-sha` in the location specified by the `$SSHA_USERS_FILE` environment variable.  Accepts HTTP requests with POST parameters `username` and `password` and attempts to decrypt the given user's random password with the supplied password.

### Encryption Details

The random password is encrypted using the secret box construction from NaCl (XSalsa20 with Poly1305). The encryption key is derived from the SHA-1 portion of the SSHA hash using scrypt with a 32 byte random salt and parameters N=32768, r=8 and p=1. The nonce is all zeroes because the key is single-use and derived using a random salt.
