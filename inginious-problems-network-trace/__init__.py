import json
import os
import traceback
from copy import deepcopy
import itertools
from random import Random

import dpkt
import web
from dpkt.ethernet import ETH_TYPE_IP, ETH_TYPE_IP6
from inginious.frontend.parsable_text import ParsableText
from yaml import load
from inginious.common.tasks_problems import Problem
from inginious.frontend.task_problems import DisplayableProblem
from quic_tracker.dissector import parse_packet_with

_dir_path = os.path.dirname(os.path.abspath(__file__))


class StaticMockPage(object):
    def GET(self, path):
        if not os.path.abspath(_dir_path) in os.path.abspath(os.path.join(_dir_path, path)):
            raise web.notfound()

        try:
            with open(os.path.join(_dir_path, 'static', path), 'rb') as file:
                return file.read()
        except:
            raise web.notfound()

    def POST(self, path):
        return self.GET(path)


class NetworkTraceProblem(Problem):
    def __init__(self, task, problemid, content, translations=None):
        self._problemid = problemid
        self._task = task
        self._trace = transform_pcap(task, content.get('pcap', ''), content.get('range', 'network'))
        self._hidden_fields = content.get('hide', {})  # The fields to be hidden
        self._field_feedback = content.get('feedback', {})
        self._header = content.get('header', '')
        self._shuffle = content.get('shuffle', False)
        self._shuffle_feedback = (content.get('shuffle-feedback') or '').strip() or 'The order of packets is incorrect'
        Problem.__init__(self, task, problemid, content, translations)

    @classmethod
    def get_type(cls):
        return 'network-trace'

    def input_is_consistent(self, task_input, default_allowed_extension, default_max_size):
        return all('{}:{}:{}'.format(self._problemid, p_idx, f) in task_input for p_idx in self._hidden_fields for f in self._hidden_fields[p_idx])

    def input_type(self):
        return list

    def check_answer(self, task_input, language):
        trace = dissect_problem(self._trace)

        feedbacks = {}
        erroneous_fields = set()
        hidden_fields = {}

        packet_order = task_input.pop(self._problemid, [])
        order_is_correct = True
        for i in range(len(trace)):
            if int(packet_order[i]) != i:
                order_is_correct = False
                break

        for k in task_input:
            if not k.startswith('@') and k.startswith(self._problemid):
                p_idx, field = k.replace(self._problemid + ':', '').split(':')
                p_idx = int(p_idx)
                if p_idx not in hidden_fields:
                    hidden_fields[p_idx] = get_hidden_fields(trace[p_idx], self._hidden_fields[p_idx])
                hf = next(filter(lambda x: x[0] == field, hidden_fields[p_idx]))
                feedbacks[k] = is_equal(hf[1], task_input[k])
                if not feedbacks[k]:
                    erroneous_fields.add(field)

        packets = {p_idx: all(feedbacks[f] for f in filter(lambda x: x.startswith('{}:{}:'.format(self._problemid, p_idx)), feedbacks.keys())) for p_idx in self._hidden_fields}

        problem_feedback = ('\n'.join(["- **{}**: {}".format(f, self._field_feedback[f]) for f in erroneous_fields])) + '\n'

        if not order_is_correct:
            problem_feedback += '\n\n{}\n\n'.format(self._shuffle_feedback)

        return sum(feedbacks.values()) == len(feedbacks) and order_is_correct, problem_feedback, [json.dumps({'fields': feedbacks, 'packets': packets})], 0

    @classmethod
    def parse_problem(cls, problem_content):
        problem_content = Problem.parse_problem(problem_content)
        try:
            problem_content['hide'] = load(problem_content['hide']) or {}
        except ValueError as e:
            raise ValueError('Hide fields does not contain valid YAML: %s' % e)
        try:
            problem_content['feedback'] = load(problem_content['feedback']) or {}
        except ValueError as e:
            raise ValueError('Feedback does not contain valid YAML: %s' % e)
        problem_content['shuffle'] = problem_content.get('shuffle') == 'on'
        if problem_content.get('range', '').strip():
            r = problem_content.get('range').strip()
            values = ('network', 'transport', 'application', 'network-transport', 'network-application', 'transport-application')
            if r not in values:
                raise ValueError('The network layers selected must be a value in ' + repr(values))
            problem_content['range'] = r
        return problem_content

    @classmethod
    def get_text_fields(cls):
        return {'name': True}


def is_equal(expected, actual):
    try:
        if type(expected) is int:
            return expected == int(actual, base=0)
    except:
        pass
    return expected == actual


class DisplayableNetworkTraceProblem(NetworkTraceProblem, DisplayableProblem):
    def __init__(self, task, problemid, content, translations=None):
        NetworkTraceProblem.__init__(self, task, problemid, content, translations)

    @classmethod
    def get_type_name(self, gettext):
        return gettext("network-trace")

    @classmethod
    def get_renderer(cls, template_helper):
        """ Get the renderer for this class problem """
        return template_helper.get_custom_renderer(os.path.join(os.path.dirname(__file__), 'templates'), False)

    def show_input(self, template_helper, language, seed):
        rand = Random("{}#{}#{}".format(self.get_task().get_id(), self.get_id(), seed))
        try:
            trace = dissect_problem(self._trace)
            trace = hide(trace, self._hidden_fields)
        except Exception as e:
            traceback.print_exc()
            trace = None
        stream = []
        for i, p in enumerate(self._trace):
            stream.append((i, len(p), get_summary(trace[i][1]), 'incomplete' if i in self._hidden_fields else 'complete'))
        trace = list(enumerate(trace))
        if self._shuffle:
            s = rand.getstate()
            rand.shuffle(stream)
            rand.setstate(s)
            rand.shuffle(trace)
        return str(DisplayableNetworkTraceProblem.get_renderer(template_helper).network_trace(self.get_id(), ParsableText.rst(self._header), trace, stream, self._shuffle, type=type, tuple=tuple))

    @classmethod
    def show_editbox(cls, template_helper, key):
        return DisplayableNetworkTraceProblem.get_renderer(template_helper).network_trace_edit(key)

    @classmethod
    def show_editbox_templates(cls, template_helper, key):
        return ""


def split_every_n(string, n=2):
    return [''.join(x) for x in zip(*[iter(string)]*n)]


def dissect_problem(trace):
    with open(os.path.join(_dir_path, 'protocols', 'all.yaml')) as f:
        protocols = load(f)
    return [(split_every_n(bytearray(p).hex()), parse_packet_with(bytearray(p), deepcopy(protocols), context={})) for p in trace]


def get_hidden_fields(packet, hidden_fields):
    fields = []
    for h in hidden_fields:
        hide_field(packet[1][0], h, fields)
    return fields


def hide(trace, hidden_fields):
    for i, (data, dissection) in enumerate(trace):
        if i in hidden_fields:
            fields = []
            for h in hidden_fields[i]:
                trace[i] = (data, [hide_field(d, h, fields) for d in trace[i][1]])
            for f in fields:
                for j in range(f[2], f[3]):
                    data[j] = '??'
    return trace


def hide_field(dissection, field_name, hidden_fields):
    if dissection[0] == field_name:
        hidden_fields.append(dissection)
        return dissection[0], '??', dissection[2], dissection[3]
    elif type(dissection[1]) is list:
        if len(dissection) == 4:
            return dissection[0], [hide_field(d, field_name, hidden_fields) for d in dissection[1]], dissection[2] , dissection[3]
        else:  # TODO: This is not specified in the dissector and should be investigated
            return dissection[0], [hide_field(d, field_name, hidden_fields) for d in dissection[1]]
    elif type(dissection[1]) is tuple:
        return dissection[0], hide_field(dissection[1], field_name, hidden_fields), dissection[2], dissection[3]
    else:
        return dissection


def get_summary(dissection):
    summary_fields = {'TCP': {'NS': 'flag', 'CWR': 'flag', 'ECE': 'flag', 'URG': 'flag', 'ACK': 'flag', 'PSH': 'flag', 'RST': 'flag', 'SYN': 'flag', 'FIN': 'flag', 'Sequence Number': {'name': 'SEQ'}, 'Acknowledgment Number': {'name': 'ACK'}, 'Options': {'Maximum Segment Size': 'MSS', 'Sack-Permitted Option': 'SACK_PERM', 'Timestamps Option': 'TS', 'Window Scale Option': 'WSO', 'No-Operation': None}}}
    base_format = '<{name}: {details}>'

    struct_name = dissection[0][0] if type(dissection[0][1]) is not tuple or dissection[0][1][0] == '' else dissection[0][1][0]
    fields = summary_fields.get(struct_name, [])
    flags = []
    values = []
    options = []
    for f, v, _, _ in dissection[0][1][1]:
        if f in fields:
            if fields[f] == 'flag':
                if v == 1:
                    flags.append(f)
            elif len(fields[f]) == 1:
                values.append((fields[f]['name'], v))
            elif fields[f].get(v[0], v[0]) is not None:
                options.append(fields[f].get(v[0], v[0]))

    if not flags and not values:
        for f in dissection[0][1][1]:
            try:
                return get_summary([f])
            except:
                pass

    return base_format.format(name=struct_name, details=', '.join(itertools.chain(flags, ('{}: {}'.format(n, v) for n, v in values), options)))


def transform_pcap(task, filename, level_range):
    _levels = {
        'network': 0,
        'transport': 1,
        'application': 2
    }
    levels = [_levels[s] for s in level_range.split('-')]
    output = []

    fs = task.get_fs()
    if not fs.exists(filename) or not fs:
        return []
    try:
        f = fs.get_fd(filename)
    except IOError:
        return []
    pcap = dpkt.pcap.Reader(f)
    for _, buf in pcap:
        try:
            struct = dpkt.ethernet.Ethernet(buf)
            s_type = struct.type
        except dpkt.dpkt.Error:
            struct = dpkt.sll.SLL(buf)
            s_type = struct.ethtype

        if s_type not in (ETH_TYPE_IP, ETH_TYPE_IP6):  # This may not be an Ethernet frame
            if (buf[0] & 0xF0) >> 4 is 4:
                struct = dpkt.ip.IP(buf)
            elif (buf[0] & 0xF0) >> 4 is 6:
                struct = dpkt.ip.IP6(buf)
            else:
                break
            buf = b''.join(struct.pack().rsplit(bytes(struct.data))) if type(struct) is not bytes and struct.data else bytes(struct)
            level = 1
        else:
            buf = b''
            level = 0

        while level <= levels[-1]:
            struct = struct.data
            if level >= levels[0]:
                buf += b''.join(struct.pack().rsplit(bytes(struct.data))) if type(struct) is not bytes and struct.data else bytes(struct)
            elif level == levels[-1]:
                buf += struct.pack()
            level += 1

        if buf:
            output.append(buf)
    f.close()

    return output


def init(plugin_manager, course_factory, client, plugin_config):
    """ Init the plugin """
    plugin_manager.add_page('/plugins/network-trace/static/(.+)', StaticMockPage)
    plugin_manager.add_hook("javascript_header", lambda: "/plugins/network-trace/static/network-trace.js")
    plugin_manager.add_hook("css", lambda: "/plugins/network-trace/static/network-trace.css")
    plugin_manager.add_hook("javascript_header", lambda: "/plugins/network-trace/static/js-yaml.min.js")
    plugin_manager.add_hook("javascript_header", lambda: "/plugins/network-trace/static/datatables.min.js")
    plugin_manager.add_hook("css", lambda: "/plugins/network-trace/static/datatables.min.css")
    course_factory.get_task_factory().add_problem_type(DisplayableNetworkTraceProblem)
