import json
import os
from copy import deepcopy
from random import Random

import web
from inginious.common.tasks_problems import Problem
from inginious.frontend.parsable_text import ParsableText
from inginious.frontend.task_problems import DisplayableProblem
from quic_tracker.dissector import parse_packet_with
from yaml import load as yload, SafeLoader

from .parse_tshark import parse_trace

_dir_path = os.path.dirname(os.path.abspath(__file__))


def load(stream):
    return yload(stream, Loader=SafeLoader)


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
        self._trace = load_trace(task, content.get('trace', ''), content.get('exclude', None))
        self._hidden_fields = content.get('hide', {})  # The fields to be hidden
        self._redacted_fields = content.get('redact', {})
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
        trace = self._trace

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
                    erroneous_fields.add((hf[0], hf[4]))

        packets = {p_idx: all(feedbacks[f] for f in filter(lambda x: x.startswith('{}:{}:'.format(self._problemid, p_idx)), feedbacks.keys())) for p_idx in self._hidden_fields}

        problem_feedback = ('\n'.join(["- **{}**: {}".format(n, self._field_feedback[f]) for f, n in erroneous_fields if f in self._field_feedback])) + '\n'

        if not order_is_correct:
            problem_feedback += '\n\n{}\n\n'.format(self._shuffle_feedback)

        return sum(feedbacks.values()) == len(feedbacks) and order_is_correct, problem_feedback, [json.dumps({'fields': feedbacks, 'packets': packets})], 0

    @classmethod
    def parse_problem(cls, problem_content):
        problem_content = Problem.parse_problem(problem_content)
        try:
            problem_content['exclude'] = load(problem_content['exclude']) or {}
        except ValueError as e:
            raise ValueError('Exclude fields does not contain valid YAML: %s' % e)
        try:
            problem_content['redact'] = load(problem_content['redact']) or {}
        except ValueError as e:
            raise ValueError('Redacted fields does not contain valid YAML: %s' % e)
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

    @classmethod
    def prepare_feedback(cls, feedback, show_everything, translation):
        return feedback


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
        stream = []
        trace = [(split_every_n(data.hex()), dissection) for data, dissection in self._trace]
        trace = list(enumerate(hide(redact(trace, self._redacted_fields), self._hidden_fields)))
        for i, p in trace:
            stream.append((i, len(p[0]), get_summary(p[1]), 'incomplete' if i in self._hidden_fields else 'complete'))
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


def load_trace(task, filename, excluded=None):
    fs = task.get_fs()
    if not fs.exists(filename) or not fs:
        return []
    try:
        f = fs.get_fd(filename)
        trace = parse_trace(f.read(), excluded=excluded)
        f.close()
        return trace
    except IOError:
        return []


def get_summary(packet):
    return packet[-1][0]['showname']


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
            for _, _, lo, hi, *_ in fields:
                for j in range(lo, hi):
                    data[j] = '??'
    return trace


def redact(trace, redacted_fields):
    for i, (data, dissection) in enumerate(trace):
        for h in redacted_fields:
            trace[i] = (data, [redact_field(d, h) for d in trace[i][1]])
    return trace


def extract_field_name_from(showname):
    if '=' in showname:
        showname = showname[showname.index('=')+1:]
    if ':' in showname:
        showname = showname[:showname.rindex(':')]
    return showname.strip()


def hide_field(d, to_hide, hidden_fields):
    field, embedded_fields = d
    if field.get('name') == to_hide:
        field['showname'] = field['showname'].replace(field['show'], '?')
        if '=' in field['showname'] and ':' in field['showname']:
            idx = field['showname'].rindex(':')
            field['showname'] = field['showname'][:idx].replace('0', '?').replace('1', '?') + ': ?'
        field['hidden'] = True
        hidden_fields.append((field['name'], field['show'], int(field['pos']), int(field['pos']) + int(field['size']), extract_field_name_from(field['showname'])))

    return field, [hide_field(embedded_field, to_hide, hidden_fields) for embedded_field in embedded_fields]


def redact_field(d, to_redact):
    field, embedded_fields = d
    if field.get('name') == to_redact:
        field['showname'] = field['showname'].replace(field['show'], '')
        if ':' in field['showname']:
            idx = field['showname'].rindex(':')
            field['showname'] = field['showname'][:idx]
        field['redacted'] = True

    return field, [redact_field(embedded_field, to_redact) for embedded_field in embedded_fields]


def init(plugin_manager, course_factory, client, plugin_config):
    """ Init the plugin """
    plugin_manager.add_page('/plugins/network-trace/static/(.+)', StaticMockPage)
    plugin_manager.add_hook("javascript_header", lambda: "/plugins/network-trace/static/network-trace.js")
    plugin_manager.add_hook("css", lambda: "/plugins/network-trace/static/network-trace.css")
    plugin_manager.add_hook("javascript_header", lambda: "/plugins/network-trace/static/js-yaml.min.js")
    plugin_manager.add_hook("javascript_header", lambda: "/plugins/network-trace/static/datatables.min.js")
    plugin_manager.add_hook("css", lambda: "/plugins/network-trace/static/datatables.min.css")
    course_factory.get_task_factory().add_problem_type(DisplayableNetworkTraceProblem)
