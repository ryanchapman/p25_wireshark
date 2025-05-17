# p25_wireshark

This is a lua Wireshark plugin for the APCO Project 25 protocol.  Inside of Wireshark, it is known as `p25cai`, which 
stands for Project 25 Common Air Interface.

## Installation

Copy `p25cai.lua` to your user plugin directory.  To find your personal plugin directory, in Wireshark, go to Help > About (on a Mac, Wireshark > About Wireshark).
Under the Folders tab, you'll see `Personal Plugins`.  

For example, on macOS, the plugin directory is probably `~/.local/lib/wireshark/plugins/`

On Windows, the plugin directory is something like `C:\Users\user1\AppData\Roaming\Wireshark\plugins` where `user1` is your Windows username.

## Sending p25 Traffic from op25 to Wireshark

Assuming you have Wireshark running on the machine at 172.20.1.150, this command would start op25 using an RTL-SDR Blog v4, and forward the frames on udp port 23456.
In Wireshark, you should set the capture filter to `udp port 23456`
```
user1@vm:/usr/src/op25/op25/gr-op25_repeater/apps$ ./rx.py --args='rtl=0' -N 'lna:40' -S 960000 -f 864.9625e6 -l http:0.0.0.0:9999 -T trunk.tsv -q -1 -v 1 -O default -w -W 172.20.1.150
```

One bit of tribal knowledge that I didn't know initially, and isn't always mentioned in examples, is that 
many of the RTL-SDR devices cannot accurately tune to the frequency you provided.  You have to figure out how much
your device is "off" then tell `rx.py` to adjust be that amount.  This is usually done with the `-q` parameter.  
Search on the internet for how to determine how much you are off using a program like SDR++ or Gqrx.
If you don't want to do that and just "wing it," you can try `-q -4` then `-q -3`, `-q -2`, `-q -1`, `-q 0`, `-q 1`,
`-q 2`, `-q 3`, `-q 4`.

## Plugin Preferences

Go into Wireshark preferences, Protocols, P25CAI

Here, you can change:

Debug Level - can be Disabled, Level 1, or Level 2

Port number - default is 23456

[x] filter enabled - you can disable the plugin if you need to; for example if the plugin is slowing down Wireshark with high traffic volumes.


## Wireshark Filters

Here a few display filters that I've found useful for looking for specific traffic.

`p25cai.algid == 0x80` - unencrypted packets
`p25cai.algid == 0xAA` - traffic encrypted using ADP (ARC4)
`p25cai.imbe` - packets with IMBE voice

`p25cai.hdu`  - packets of type `Header Data Unit`
`p25cai.ldu1` - packets of type `Logical Link Data Unit 1`
`p25cai.ldu2` - packets of type `Logical Link Data Unit 2`
`p25cai.lcf`  - packets of type `Terminator with Link Control`
`p25cai.tsbk` - packets of type `Trunking Signaling Data Unit`

## Development

The information below is useful if you are interested in improving the p25cai lua plugin.

### Rapid lua development

One nice feature with lua plugins is how fast you can make changes.  
For example, make a change to `~/.local/lib/wireshark/plugins/p25cai.lua`, then in Wireshark, 
press `Cmd + Shift + L` and Wireshark will reload the lua script immediately.

### P25 Documentation

The P25 protocol is documented in TIA-102:

TIA-102-AAAD - Block Encryption Protocol
TIA-102-AABB - Trunking Protocol Channel Formats
TIA-102-AABC - Trunking Control Channel Messages
TIA-102-AABF - Link Control Word Formats and Messages
TIA-102-AACE - Link Layer Authentication
TIA-102-BAAA - Common Air Interface (CAI) (FDMA)
TIA-102-BAAC - Common Air Interface Reserved Values
TIA-102-BABA - IMBE Vocoder Description
TIA-102-BABC - Vocoder Reference Test
TIA-102-BAHA - Fixed Station Interface
TIA-102-BBAB - Phase 2 Two-Slot Time Division Multiple Access Physical Layer Protocol Specification
TIA-102-BBAC - Phase 2 Two-Slot TDMA Media Access Control Layer Description
TIA-102-CAAA - Digital C4FM/CQPSK Transceiver Measurement Methods
TIA-102-CAAB - Transceiver Performance Recommendations
