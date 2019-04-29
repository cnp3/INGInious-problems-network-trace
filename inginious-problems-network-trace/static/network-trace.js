window['studio_init_template_network-trace'] = function (well, pid, problem) {
    if ('trace' in problem)
        $('#trace-' + pid, well).val(problem['trace']);
    if ('hide' in problem)
        $('#hide-' + pid, well).val(jsyaml.safeDump(problem['hide'], {condenseFlow: true}).replace(/\'/gm, ''));
    if ('exclude' in problem)
        $('#exclude-' + pid, well).val(jsyaml.safeDump(problem['exclude'], {condenseFlow: true}).replace(/\'/gm, ''));
    if ('redact' in problem)
        $('#redact-' + pid, well).val(jsyaml.safeDump(problem['redact'], {condenseFlow: true}).replace(/\'/gm, ''));
    if ('feedback' in problem)
        $('#feedback-' + pid, well).val(jsyaml.safeDump(problem['feedback'], {condenseFlow: true}).replace(/\'/gm, ''));
    if ('pcap' in problem)
        $('#pcap-' + pid, well).val(problem['pcap']);
    if ('range' in problem)
        $('#range-' + pid, well).val(problem['range']);
    if ('shuffle' in problem && problem['shuffle'])
        $('#shuffle-' + pid, well).attr('checked', '');
    if ('shuffle-feedback' in problem)
        $('#shuffle-feedback-' + pid, well).val(problem['shuffle-feedback']);
};
window['load_input_network-trace'] = function (submissionid, key, input) {
    const table = $('#table-' + key).find('tbody');
    const order = input[key];
    var rows = table.children('tr');
    rows.sort(function (a, b) {
        return parseInt(a.children[0].getAttribute('value')) - parseInt(b.children[0].getAttribute('value'));
    });
    table.append(rows);
    rows = table.children('tr');
    table.append($.map(order, function (i) {return rows[parseInt(i)]}));
    for (const k in input) {
        if (input.hasOwnProperty(k) && !k.startsWith('@')) {
            $('input[name="' + k +'"]').not('[type="hidden"]').val(input[k]);
        }
    }
};
window['load_feedback_network-trace'] = function (problemid, content) {
    const feedback = jQuery.parseJSON($('<div>').html(content[1]).text());
    const fields = feedback.fields;
    const packets = feedback.packets;

    $('span.feedback[data-field]').removeClass('alter-danger').removeClass('alert-success').html();
    $('span.packet-status[data-packet-number]').html();

    for (const k in fields) {
        if (fields.hasOwnProperty(k)) {
            if (fields[k]) {
                $('span.feedback[data-field="' + k + '"]').removeClass('alert-danger').addClass('alert-success').html('Valid');
            } else {
                $('span.feedback[data-field="' + k + '"]').removeClass('alert-success').addClass('alert-danger').html('Invalid');
            }
        }
    }

    for (const k in packets) {
        if (packets.hasOwnProperty(k)) {
            if (packets[k]) {
                $('span.packet-status[data-packet-number="' + k + '"]').html(' <i class="fa fa-check" style="color: #43ac6a"></i>')
            } else {
                $('span.packet-status[data-packet-number="' + k + '"]').html(' <i class="fa fa-times" style="color: #f04124;"></i>')
            }
        }
    }
};