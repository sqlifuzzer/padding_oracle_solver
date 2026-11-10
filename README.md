# Padding Oracle Solver

A Padding Oracle exploitation script in Python intended to be easy and flexible to use.
 - Designed and used for CTFs where simplicity (HA!) and speed are paramount.
 - Minimal imports: should not require external dependencies / installation. `cat > ` it onto your machine and run it.
 - Minimal functionality compared to ORCA - no fancy HTTP2 time based detection.
 - No command line input - you modify one function (which interfaces with your target however you like - that's your job!), and paste your payload into the script.
 - The solver deals with multi- or single- block payloads, just give it the full payload and set the block size, it will do the rest.

# How To

1. Go to check_for_padding_error(full_encrypted_bytes) modify this to send in the payload, get the response, and return one or many things that change.
2. Add your encypted bytes in the line below the '### YOUR PAYLOAD GOES HERE:' comment 
