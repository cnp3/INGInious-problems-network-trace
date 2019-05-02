INGInious-problems-network-trace
================================

## Installing

    pip3 install --upgrade git+https://github.com/CNP3/INGInious-problems-network-trace

## Activating

In your ``configuration.yaml`` file, add the following plugin entry:

    plugins:
      - plugin_module: "inginious-problems-network-trace"
      
## How to create a `network-trace` problem

##### 1. Create a PDML file

First, create a [PDML](https://wiki.wireshark.org/PDML) file containing the network packets used for the problem. This can be done conveniently using `tshark`. `tshark -T pdml -r file.pcap -J "tcp"` converts `file.pcap` to PDML. One can use Wireshark options, e.g. `-o tcp.relative_sequence_numbers:FALSE` to disable the relative sequence numbers computation. Upload the resulting file to the task files and fill in its name in the problem configuration. At this stage, the captured packets should be displayed when viewing the task.

##### 2. Fill in the fields that should be excluded

The *Exclude fields* parameter takes a list of field names that should be completely excluded from the packet trace. E.g.:

``` yaml
- tcp.flags.str
- tcp.window_size
- tcp.window_size_scalefactor
- tcp.len
- tcp.checksum
```

##### 3. Fill in the fields that should be redacted

Some fields are useful to understand the protocol wire format, but can reveal information that interfere with the exercise. The *Redact fields* parameter takes a list of fields names that will be redacted from the packet trace, in the same format as *Exclude fields*.

##### 4. Fill in the fields for which their value will be hidden

For each packet, one can choose the packets and the fields that need to be filled in for the exercise. E.g.

``` yaml
1:
  - tcp.ack
  - tcp.flags.ack
```

This will hide the value of the `Acknowledgment Number` and the `ACK` flags to students. Completing the exercise requires filling in these values.

##### 5. Write up the feedback for each hidden field

For each field that were chosen to be hidden in the previous step, one can write up a dedicated feedback that will be displayed when an erroneous value is submitted for a particular field. E.g.


``` yaml
tcp.ack: The Acknowledgement Number is defined in `Section 3.1 of RFC793 <https://tools.ietf.org/html/rfc793>`_
tcp.flags.ack: The ACK flag is set whenever the Acknowledgment Number field is to be considered signficant.
```

One can use reStructuredText to format the feedback.

##### 6. Choose whether the exercise involves reordering the packets

Click the *Shuffle packets* checkbox to enable packet reordering for this exercise. The students then must fill in the correct values for hidden fields as well as reorder the packets correctly. Use the last configuration field to write up the feedback that will be displayed when the wrong order is submitted.
