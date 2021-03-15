# NAME
**ssh-keyget** - get SSH public key from server

# SYNOPSIS
**ssh-keyget**
[*host:port*]
[*type(dsa,rsa,ecdsa,ed25519)*]
[*export(e)*]

# DESCRIPTION
**ssh-keyget**
is a utility for getting the SSH public key from a server.

**ssh-keyget**
does not need login access to the server.

The options are as follows:

*type*

> Specify the type of the key to fetch from the server.
> The possible values are
> "dsa",
> "rsa",
> "ecdsa",
> "ed25519".


*export*

> Option "e" will output the public key in
> "RFC4716"
> format. This option allows exporting keys for use by other programs.


If a public key obtained using
**ssh-keyget**
is used without verifying the key, users will be vulnerable to
*man in the middle*
attacks.

# FILES

*None*

# EXAMPLES

Print the RSA public key for server
*hostname*:

	ssh-keyget hostname:port rsa

Save RSA public key for server
*hostname*
in
"RFC4716"
format :

	ssh-keyget hostname:port rsa e > publickey

# SEE ALSO

ssh(1),
sshd(8)

# AUTHORS

sjp27 &lt; https://github.com/sjp27 &gt;
implemented ssh-keyget.
