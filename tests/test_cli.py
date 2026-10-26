import os
import shutil
import socket
import subprocess
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'click-jackalope.sh'

class FrameParser(HTMLParser):
    def handle_starttag(self, tag, attrs):
        if tag == 'iframe': self.attrs = dict(attrs)

class CliTests(unittest.TestCase):
    def test_untrusted_url_stays_one_attribute_on_supported_shells(self):
        url = 'https://example.test/" onload=globalThis.sentinel=1 x="<>&'
        for shell in dict.fromkeys(['/bin/bash', shutil.which('bash')]):
            with self.subTest(shell=shell), tempfile.TemporaryDirectory() as directory:
                out = Path(directory) / 'poc.html'
                subprocess.run([shell, str(SCRIPT), '-u', url, '-f', str(out)], check=True, capture_output=True)
                parser = FrameParser()
                parser.feed(out.read_text())
                self.assertEqual(parser.attrs['src'], url)
                self.assertNotIn('onload', parser.attrs)

    # Mirrors ClickJackalopeTemplateParityTest verbatim: the shell CLI and the Java generator
    # maintain separate copies of the templates, so both must emit byte-identical iframe markup.
    PARITY_URL = 'https://example.test/" onload=globalThis.sentinel=1 x="<>&'
    PARITY_ESCAPED = 'https://example.test/&quot; onload=globalThis.sentinel=1 x=&quot;&lt;&gt;&amp;'

    def assertIframeContract(self, html, sandbox):
        expected = ('<iframe src="' + self.PARITY_ESCAPED + '" title="click-jackalope-test"'
                    + (' sandbox=""' if sandbox else '') + '></iframe>')
        self.assertIn(expected, html)

    def test_templates_match_the_java_generator_contract(self):
        for template in ('standard', 'decoy-login', 'banner-lure'):
            for sandbox in (False, True):
                with self.subTest(template=template, sandbox=sandbox), \
                        tempfile.TemporaryDirectory() as directory:
                    out = Path(directory) / 'poc.html'
                    cmd = ['bash', str(SCRIPT), '-u', self.PARITY_URL, '-t', template]
                    if sandbox:
                        cmd.append('-s')
                    subprocess.run(cmd + ['-f', str(out)], check=True, capture_output=True)
                    self.assertIframeContract(out.read_text(), sandbox)

    def test_busy_port_reports_cause_without_claiming_to_serve(self):
        with socket.socket() as occupied, tempfile.TemporaryDirectory() as directory:
            occupied.bind(('127.0.0.1', 0))
            occupied.listen()
            result = subprocess.run(['bash', str(SCRIPT), '-u', 'https://example.test', '-S', str(occupied.getsockname()[1]), '-f', str(Path(directory)/'poc.html')], capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Could not start', result.stderr)
            self.assertNotIn('Serving PoC at', result.stdout)
