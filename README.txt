

NAME


SSH-KEYGET - get SSH public key from server



SYNOPSIS


SSH-KEYGET [_host:port_][_type(rsa,dsa,ecdsa,ed25519)_] [_export(e)_]



DESCRIPTION


SSH-KEYGET is a utility for getting the SSH public key from a server.

SSH-KEYGET does not need login access to the server.

The options are as follows:

_type_

  Specify the type of the key to fetch from the server. The possible
  values are "rsa", "dsa", "ecdsa", "ed25519".

_export_

  Option "e" will output the public key in "RFC4716" format. This option
  allows exporting keys for use by other programs.

If a public key obtained using SSH-KEYGET is used without verifying the
key, users will be vulnerable to _man in the middle_ attacks.



FILES


_None_



EXAMPLES


Print the RSA public key for server _hostname_:

    ssh-keyget hostname:port rsa

Save RSA public key for server _hostname_ in "RFC4716" format :

    ssh-keyget hostname:port rsa e > publickey



SEE ALSO


ssh(1), sshd(8)



AUTHORS


sjp27 < https://github.com/sjp27 > implemented ssh-keyget.
