# Advanced Encryption Standard (AES)
This is a collection of an AES VHDL package, an encrypt module, and a decrypt
module. The default configuration is for `Nr=14` and `Nb=8`, for AES-256. This
can be re-purposed for both AES-128 and AES-192 by adjusting these values.
## Implementation
The encrypt and decrypt modules are designed not to produce the expanded key
ahead of time. The inverse cipher reverses the key schedule and uses inverse
operations in a different order from the forwards round, as per FIPS-197 5.3. 
The inverse cipher of 5.3.5 could be constructed using this AES package.

All intermediate data is meant to be cleared at the end of the operation, with
the output data remaining on the bus until explicitly cleared.

The `en` signal indicates whatever key and text is available on the input bus
shall be latched and the cipher shall restart. The encryptor/decryptor will
only advance to round 1 once the `en` signal is set low.
## Test Benches
Test benches are provided to demonstrate the basic functionality of each of
modules and the package. This is by no means an accredited implementation.
