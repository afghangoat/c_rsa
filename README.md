#C RSA implementation

A full implementation of the RSA encryption algorithm in the C language.

##Constraints:
`priv_key.key_size_e` must be smaller than N
Please note that in order to work with larger numbers, such as 1024 or 4096 bit keys, not even unsigned long long int will do it.
arbitrary-precision arithmetic common libraries: include <gmp.h> is recommended for this task

`prob_tries`: How much tries should the Fermat prime test do?

Also, there is a `rsa_create_OAEP_padding` experimental function which helps to make the algorithm more secure.

##Usage

Run:
`gcc rsa.c -o rsa`
`./rsa`