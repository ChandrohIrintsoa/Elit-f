
"""Tests de la session r2 persistante (protocole r2pipe interne).

Avant : chaque commande r2 relançait `r2 -q -N -c <cmd>` → le seek (`s`)
était perdu entre deux commandes (pd200 retombait sur entry0 → « invalid »).
Maintenant : un processus r2 -q0 persistant conserve seek/flags/analyse.
"""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import elitf_r2 as r2
from elitf_ui import LogManager


FAKE_R2 = r'''#!/usr/bin/env python3
"""Émule `r2 -q0 [-w] <fichier>` : une commande par ligne, sortie + \\0."""
import os, sys

path = sys.argv[-1]
received = []
log = os.environ.get('FAKE_R2_LOG')
cfg = {}
seek = 0
blocked = os.environ.get('FAKE_R2_BLOCK')


def out(t):
    sys.stdout.buffer.write(t.encode('utf-8', 'replace'))
    sys.stdout.buffer.write(b'\x00')
    sys.stdout.buffer.flush()


def note():
    if log:
        with open(log, 'a', encoding='utf-8') as f:
            f.write(repr(received) + '\n')


if blocked:
    time.sleep(float(blocked))

while True:
    line = sys.stdin.readline()
    if not line:
        break
    c = line.rstrip('\n')
    if not c:
        continue
    received.append(c)
    if c == 'q':
        note()
        break
    if c.startswith('e '):
        kv = c[2:].split('=', 1)
        if len(kv) == 2:
            cfg[kv[0]] = kv[1]
            out('')  # e k=v est silencieux mais émet le NUL
        elif kv[0] in cfg:
            out(str(cfg[kv[0]]))
        else:
            out('')
    elif c.startswith('s '):
        try:
            seek = int(c[2:], 16)
        except ValueError:
            pass
        out('')  # r2 émet toujours un NUL, même pour une sortie vide
    elif c.startswith('pd') or c.startswith('px'):
        out('%s seek=%#x %s' % (os.path.basename(path), seek, c))
    elif c == 'pconf':
        out('; '.join('%s=%s' % (k, v) for k, v in sorted(cfg.items())))
    else:
        out('ok:%s' % c)
    note()
'''


class FakeUI:
    console = None

    def __init__(self, lines=()):
        self.lines = list(lines)
        self.printed = []

    def _print(self, *a, **k):
        self.printed.append(" ".join(str(x) for x in a))

    def r2_readline(self, prompt=""):
        if not self.lines:
            return None
        return self.lines.pop(0)

    def confirm(self, question, default=False):
        return default


def _make_session(root, lines=(), targets=None, env=None):
    if targets is None:
        so = root / 'libapp.so'
        so.write_bytes(b'ELF-PAYLOAD')
        targets = [{'name': 'libapp.so', 'path': str(so)}]
    ui = FakeUI(lines)
    for key, value in (env or {}).items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    return r2.R2Session(targets, str(root / 'out'), LogManager(), ui), ui


class R2PipeTests(unittest.TestCase):
    def setUp(self):
        self._env_backup = dict(os.environ)
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.shim = self.root / 'fake_r2.py'
        self.shim.write_text(FAKE_R2, encoding='utf-8')
        self.shim.chmod(0o755)
        self.log = self.root / 'cmds.log'

    def tearDown(self):
        self.temp.cleanup()
        os.environ.clear()
        os.environ.update(self._env_backup)

    def test_seek_persists_between_commands(self):
        session, _ = _make_session(self.root, env={'FAKE_R2_LOG': str(self.log),
                                                   'R2_TIMEOUT': '20'})
        session.r2_bin = str(self.shim)
        rc1, _, err1 = session.run_r2('s 0x6f57ec')
        self.assertEqual(rc1, 0, err1)
        rc2, out2, err2 = session.run_r2('pd 1')
        self.assertEqual(rc2, 0, err2)
        # CŒUR DU BUG : le seek de la commande précédente est conservé
        self.assertIn('seek=0x6f57ec', out2)

    def test_no_nul_in_output(self):
        session, _ = _make_session(self.root, env={'FAKE_R2_LOG': str(self.log),
                                                   'R2_TIMEOUT': '20'})
        session.r2_bin = str(self.shim)
        _, out, _ = session.run_r2('pd 1')
        self.assertNotIn('\x00', out)
        self.assertIn('libapp.so', out)

    def test_header_and_env_applied_once(self):
        session, _ = _make_session(self.root, env={'FAKE_R2_LOG': str(self.log),
                                                   'R2_TIMEOUT': '20'})
        session.r2_bin = str(self.shim)
        session.handle_builtin('!set e asm.bytes=true')
        session.run_r2('pd 1')
        received = eval(self.log.read_text(encoding='utf-8').splitlines()[-1])
        self.assertEqual(received[:3], r2.R2_HEADER_LINES)
        self.assertIn('e asm.bytes=true', received)
        # pas de re-émission à chaque commande (session persistante)
        session.run_r2('afl')
        received = eval(self.log.read_text(encoding='utf-8').splitlines()[-1])
        self.assertEqual(received[-1], 'afl')
        self.assertEqual(received.count('e asm.bytes=true'), 1)

    def test_no_analysis_replay_in_pipe_mode(self):
        session, _ = _make_session(self.root, env={'FAKE_R2_LOG': str(self.log),
                                                   'R2_TIMEOUT': '20'})
        session.r2_bin = str(self.shim)
        session.run_r2('aaa')
        session.run_r2('pd 1')
        received = eval(self.log.read_text(encoding='utf-8').splitlines()[-1])
        # l'analyse n'est PAS rejouée : r2 garde son état en session
        self.assertEqual(received.count('aaa'), 1)
        self.assertEqual(received[-1], 'pd 1')

    def test_fallback_when_r2_missing(self):
        session, _ = _make_session(self.root)
        session.r2_bin = '/no/such/r2'
        fake = subprocess.CompletedProcess([], 0, 'fallback-out\n', '')
        with patch.object(r2.subprocess, 'run', return_value=fake) as sp:
            rc, out, err = session.run_r2('afl')
        self.assertEqual(rc, 0)
        self.assertIn('fallback-out', out)
        argv = sp.call_args.args[0]
        self.assertEqual(argv[0], '/no/such/r2')

    def test_fallback_on_broken_shim(self):
        # shim qui meurt immédiatement (fichier vide) → repli sans crash
        broken = self.root / 'broken_r2.py'
        broken.write_text('#!/usr/bin/env python3\n')
        broken.chmod(0o755)
        session, _ = _make_session(self.root, env={'R2_TIMEOUT': '10'})
        session.r2_bin = str(broken)
        fake = subprocess.CompletedProcess([], 0, 'fallback-out\n', '')
        with patch.object(r2.subprocess, 'run', return_value=fake):
            rc, out, err = session.run_r2('afl')
        self.assertEqual(rc, 0)
        self.assertIn('fallback-out', out)

    def test_timeout_falls_back(self):
        session, _ = _make_session(self.root, env={'FAKE_R2_LOG': str(self.log),
                                                   'FAKE_R2_BLOCK': '8',
                                                   'R2_TIMEOUT': '1'})
        session.r2_bin = str(self.shim)
        fake = subprocess.CompletedProcess([], 0, 'fallback-out\n', '')
        start = time.time()
        with patch.object(r2.subprocess, 'run', return_value=fake):
            rc, out, err = session.run_r2('afl')
        elapsed = time.time() - start
        self.assertEqual(rc, 0)
        self.assertIn('fallback-out', out)
        self.assertLess(elapsed, 6)

    def test_rw_mode_backs_up_once_at_spawn(self):
        session, _ = _make_session(self.root, env={'FAKE_R2_LOG': str(self.log),
                                                   'R2_TIMEOUT': '20'})
        session.r2_bin = str(self.shim)
        session.handle_builtin('!rw on')
        session.run_r2('wx 00 @ 0x1000')
        session.run_r2('wx 00 @ 0x2000')
        backup = Path(str(self.root / 'libapp.so') + '.elitf.bak')
        self.assertTrue(backup.exists())
        self.assertEqual(backup.read_bytes(), b'ELF-PAYLOAD')

    def test_switch_target_reopens_pipe(self):
        so2 = self.root / 'libflutter.so'
        so2.write_bytes(b'B')
        session, _ = _make_session(
            self.root,
            targets=[{'name': 'libapp.so', 'path': str(self.root / 'libapp.so')},
                     {'name': 'libflutter.so', 'path': str(so2)}],
            env={'FAKE_R2_LOG': str(self.log), 'R2_TIMEOUT': '20'})
        session.r2_bin = str(self.shim)
        session.run_r2('pd 1')
        session.handle_builtin('!use 2')
        rc, out, _ = session.run_r2('pd 1')
        self.assertEqual(rc, 0)
        self.assertIn('libflutter.so', out)

    def test_close_terminates_pipe(self):
        session, _ = _make_session(self.root, env={'FAKE_R2_LOG': str(self.log),
                                                   'R2_TIMEOUT': '20'})
        session.r2_bin = str(self.shim)
        session.run_r2('pd 1')
        pipe = session._pipe
        self.assertIsNotNone(pipe)
        proc = pipe.proc
        session.close()
        self.assertIsNone(session._pipe)
        self.assertEqual(proc.poll(), 0)

    def test_pipe_state_after_close_reopens(self):
        session, _ = _make_session(self.root, env={'FAKE_R2_LOG': str(self.log),
                                                   'R2_TIMEOUT': '20'})
        session.r2_bin = str(self.shim)
        session.run_r2('s 0x1000')
        session.close()
        rc, out, _ = session.run_r2('pd 1')
        self.assertEqual(rc, 0)
        self.assertIn('seek=0x0', out)  # nouvelle session → seek initial

    def test_help_mentions_persistent_session(self):
        session, _ = _make_session(self.root, env={'R2_TIMEOUT': '20'})
        session.r2_bin = str(self.shim)
        session._print_help()
        text = '\n'.join(session.ui.printed)
        self.assertIn('persistante', text)


class R2PipeUnitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.shim = self.root / 'fake_r2.py'
        self.shim.write_text(FAKE_R2, encoding='utf-8')
        self.shim.chmod(0o755)

    def tearDown(self):
        self.temp.cleanup()

    def test_pipe_cmd_roundtrip(self):
        pipe = r2.R2Pipe(str(self.shim), str(self.root / 'x.so'))
        try:
            self.assertEqual(pipe.cmd('pconf'), '')
            self.assertEqual(pipe.cmd('e asm.bytes=true'), '')
            self.assertEqual(pipe.cmd('pconf'), 'asm.bytes=true')
        finally:
            pipe.close()

    def test_pipe_timeout_raises(self):
        os.environ['FAKE_R2_BLOCK'] = '6'
        try:
            pipe = r2.R2Pipe(str(self.shim), str(self.root / 'x.so'))
            try:
                with self.assertRaises(r2.R2PipeError):
                    pipe.cmd('pd 1', timeout=1)
            finally:
                pipe.close()
        finally:
            os.environ.pop('FAKE_R2_BLOCK', None)


if __name__ == '__main__':
    unittest.main()
