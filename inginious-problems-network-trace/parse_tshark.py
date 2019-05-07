from defusedxml.ElementTree import fromstring


def flatten(l):
    for f, nf in l:
        yield f
        if isinstance(nf, list):
            yield from flatten(nf)
        else:
            yield nf


def parse_field(field, excluded):
    if field is None or not int(field.attrib.get('size', 0)) or field.attrib.get('hide') == 'yes':
        return

    return field.attrib, [parse_field(f, excluded) for f in field.findall('field') if parse_field(f, excluded) is not None and f.attrib.get('name') not in excluded]


def reconstruct_payload(captured_size, packet):
    a = bytearray(captured_size)

    lowest, highest = captured_size, 0
    for e in flatten(packet):
        if 'value' not in e:
            continue
        l, h = int(e['pos']), int(e['pos'])+int(e['size'])
        a[l:h] = bytes.fromhex(e.get('unmaskedvalue', e['value']))
        if l < lowest:
            lowest = l
        if h > highest:
            highest = h

    for e in flatten(packet):
        e['pos'] = str(int(e['pos']) - lowest)

    return a[lowest:highest]


def parse_trace(trace_string, excluded=None):
    if excluded is None:
        excluded = set()
    trace = []
    for e in fromstring(trace_string).findall('packet'):
        packet_layers = []
        captured_size = int(e.find("proto[@name='geninfo']").attrib['size'])
        for p in e.findall('proto'):
            if p.attrib['name'] != 'geninfo' and 'fake' not in p.attrib['name'] and p.find("field[@name='filtered']") is None:
                packet_layers.append(({**p.attrib}, [parse_field(f, excluded) for f in p.findall('field') if parse_field(f, excluded) is not None and f.attrib.get('name') not in excluded]))
        trace.append((reconstruct_payload(captured_size, packet_layers), packet_layers))
    return trace
