def decode(hex_byte):
    if hex_byte == '??':
        return '?'
    c = chr(int('0x' + str(hex_byte), base=16))
    return c if c.isprintable() else '.'


def print_struct(d, p_number, p_index):
    ret = ''
    for field, nested_fields in d:
        s_idx = int(field['pos'])
        e_idx = s_idx + int(field['size'])
        nested = field.get('showname', field.get('show'))
        if field.get('hidden'):
            nested += ' <input type="text" name="{id}:{pn}:{n}"> <span class="feedback" data-field="{id}:{pn}:{n}"></span>'.format(
                id=id, pn=p_index, n=field['name'])
        else:
            nested += '<ul data-start-offset="{}" data-end-offset="{}">{}</ul>'.format(s_idx, e_idx,
                                                                                       print_struct(nested_fields,
                                                                                                    p_number, p_index))

        ret += '<li data-start-offset="{}" data-end-offset="{}">{}</li>'.format(s_idx, e_idx, nested)
    return ret


def print_dissection(p_number, p, p_index):
    data, dissection = p
    size = 2 * 8
    ret = '<div class="row packet packet-{}"><div class="col-lg-6 hex-view">'.format(p_number)
    for i in range(0, len(data), size):
        ret += '<code class="address">{:04X}&nbsp;&nbsp;</code>'.format(i)
        line = data[i:i + size]
        for j in range(size):
            ret += '<code class="byte">{}</code>'.format(line[j] if j < len(line) else '&nbsp;&nbsp;')
            if j == 7:
                ret += '<code>&nbsp;&nbsp;</code>'

        ret += '<code>&nbsp;&nbsp;</code>'
        ret += '<br>'

    ret += '<hr>'

    for i in range(0, len(data), size):
        ret += '<code class="address">{:04X}&nbsp;&nbsp;</code>'.format(i)
        line = data[i:i + size]
        for j in range(size):
            ret += '<code class="char">{}</code>'.format(decode(line[j]) if j < len(line) else '&nbsp;')
        ret += '<br>'

    ret += '</div><div class="col-lg-6 structure" style="word-wrap: break-word;">'
    ret += '<ul>{}</ul>'.format(print_struct(dissection, p_number, p_index))
    return ret + '</div></div>'