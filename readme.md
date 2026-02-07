Pure Python Decoder for Ford & VAG KeyFobs, decodes Flipper Zero Raw .SUB File.

There are 2 example .sub Files to test the decoder

USAGE:
--------
Fordv0:

"python Fordv0.py 0000_Ford_ts_x4.sub"

-

VAG (VW, Audi, Seat Skoda) with full AUT64 decoder:

"python VAG.py Golf4.sub"

-
example VAG Encoder:

"VAG_Roll_the_Code.py"

this script generates a new valid unlock code based on the output of "python VAG.py Golf4.sub".
you can verify it against the output from Golf4.sub.

-

it's based/inspired by RocketGods ProtoPirate :)
