window['studio_init_template_network-trace'] = function (well, pid, problem) {
    console.log(well, pid, problem);
    if ('trace' in problem)
        $('#trace-' + pid, well).val(JSON.stringify(problem['trace']));
    if ('hide' in problem)
        $('#hide-' + pid, well).val(jsyaml.safeDump(problem['hide'], {condenseFlow: true}).replace(/\'/gm, ''));
    if ('feedback' in problem)
        $('#feedback-' + pid, well).val(jsyaml.safeDump(problem['feedback'], {condenseFlow: true}).replace(/\'/gm, ''));
};
window['load_input_network-trace'] = function (submissionid, key, input) {
    for (const k in input) {
        if (input.hasOwnProperty(k) && !k.startsWith('@')) {
            $('input[name="' + k +'"]').val(input[k]);
        }
    }
};
window['load_feedback_network-trace'] = function (problemid, content) {
    const feedback = jQuery.parseJSON($('<div>').html(content[1]).text());
    const fields = feedback.fields;
    const packets = feedback.packets;
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