#!/usr/bin/env python3
"""Real socket connections through agent-jail; no mocked sandbox decisions."""
import os
from concurrent.futures import ThreadPoolExecutor
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JAIL = str(Path(os.environ.get("AGENT_JAIL_BIN", ROOT / "zig-out/bin/agent-jail")).resolve())
CLIENT = "import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.close()"


class UnixSocketTests(unittest.TestCase):
    def setUp(self):
        # Keep paths below sockaddr_un's platform limit.
        self.tmp = tempfile.TemporaryDirectory(prefix="jail-sock-", dir="/tmp")
        self.addCleanup(self.tmp.cleanup)
        self.a = self.listener('a.sock')
        self.b = self.listener('b.sock')

    def listener(self, name):
        path = str(Path(self.tmp.name) / name)
        listener = socket.socket(socket.AF_UNIX)
        self.addCleanup(listener.close)
        listener.bind(path)
        listener.listen(64)
        return path

    def run_client(self, path, *flags):
        return subprocess.run([JAIL, *flags, '--', sys.executable, '-c', CLIENT, path],
                              capture_output=True, text=True, timeout=10)

    def test_no_flag_preserves_access(self):
        for flags in ([], ['--best-effort', '--system-ro', '--rw', self.tmp.name]):
            for path in [self.a, self.b]:
                result = self.run_client(path, *flags)
                self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS enforcement')
    def test_exact_allowlist(self):
        allowed = self.run_client(self.a, '--unix-socket', self.a)
        self.assertEqual(allowed.returncode, 0, allowed.stderr)
        denied = self.run_client(self.b, '--unix-socket', self.a)
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn('Operation not permitted', denied.stderr)

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS enforcement')
    def test_forked_descendants_cannot_connect_to_a_foreign_socket(self):
        child = subprocess.run([JAIL, '--unix-socket', self.a, '--', '/bin/sh', '-c',
                                '"$@"; status=$?; exit "$status"', 'sh', sys.executable, '-c', CLIENT, self.b],
                               capture_output=True, text=True, timeout=10)
        self.assertNotEqual(child.returncode, 0)
        self.assertIn('Operation not permitted', child.stderr)

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS enforcement')
    def test_aliases_and_repeatable_paths(self):
        alias = str(Path(self.tmp.name) / 'alias.sock')
        os.symlink(self.b, alias)
        denied = self.run_client(alias, '--unix-socket', self.a)
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn('Operation not permitted', denied.stderr)
        allowed = self.run_client(self.b, '--unix-socket', self.a, '--unix-socket', alias)
        self.assertEqual(allowed.returncode, 0, allowed.stderr)

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS enforcement')
    def test_best_effort_still_enforces_supported_restriction(self):
        result = self.run_client(self.b, '--best-effort', '--unix-socket', self.a)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Operation not permitted', result.stderr)

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS enforcement')
    def test_socket_paths_are_literal_and_missing_paths_fail(self):
        unusual = self.listener('quote"back\\\\slash.sock')
        allowed = self.run_client(unusual, '--unix-socket', unusual)
        self.assertEqual(allowed.returncode, 0, allowed.stderr)
        denied = self.run_client(self.b, '--unix-socket', unusual)
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn('Operation not permitted', denied.stderr)
        missing = self.run_client(self.a, '--best-effort', '--unix-socket', self.a + '.missing')
        self.assertEqual(missing.returncode, 1, missing.stderr)
        self.assertIn('InvalidSocketPath', missing.stderr)

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS enforcement')
    def test_filesystem_grants_do_not_override_socket_restrictions(self):
        flags = ('--rw', self.tmp.name, '--unix-socket', self.a)
        allowed = self.run_client(self.a, *flags)
        self.assertEqual(allowed.returncode, 0, allowed.stderr)
        denied = self.run_client(self.b, *flags)
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn('Operation not permitted', denied.stderr)
        prefix = self.listener('a.sock.suffix')
        denied = self.run_client(prefix, *flags)
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn('Operation not permitted', denied.stderr)

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS enforcement')
    def test_datagram_connections_and_sendto(self):
        paths = [str(Path(self.tmp.name) / name) for name in ('a.dgram', 'b.dgram')]
        for path in paths:
            receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            self.addCleanup(receiver.close)
            receiver.bind(path)
        for operation in ('s.connect(sys.argv[1])', 's.sendto(b"probe", sys.argv[1])'):
            code = 'import socket,sys; s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); ' + operation
            for path in paths:
                with self.subTest(operation=operation, path=path):
                    result = subprocess.run([JAIL, '--unix-socket', paths[0], '--',
                                             sys.executable, '-c', code, path],
                                            capture_output=True, text=True, timeout=10)
                    if path == paths[0]:
                        self.assertEqual(result.returncode, 0, result.stderr)
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn('Operation not permitted', result.stderr)

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS enforcement')
    def test_tcp_is_unaffected(self):
        listener = socket.socket()
        self.addCleanup(listener.close)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        result = subprocess.run([JAIL, '--unix-socket', self.a, '--', sys.executable,
                                 '-c', f'import socket; socket.create_connection(("127.0.0.1", {port})).close()'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS enforcement')
    def test_unicode_and_control_characters_are_literal_path_data(self):
        for name in ('汉-é-e\u0301-שלום.sock', 'quote"-slash\\-().sock', 'line\nbreak.sock'):
            with self.subTest(name=name):
                path = self.listener(name)
                allowed = self.run_client(path, '--unix-socket', path)
                self.assertEqual(allowed.returncode, 0, allowed.stderr)
                denied = self.run_client(self.b, '--unix-socket', path)
                self.assertNotEqual(denied.returncode, 0)
                self.assertIn('Operation not permitted', denied.stderr)

    def test_missing_values_are_rejected_before_starting_the_command(self):
        for flag in ('--uid', '--gid', '--hide', '--rw', '--ro', '--list', '--unix-socket', '--cwd'):
            for tail in ([], ['--', '/bin/sh', '-c', 'echo SHOULD_NOT_RUN']):
                with self.subTest(flag=flag, tail=tail):
                    result = subprocess.run([JAIL, flag, *tail], capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn('MissingValue', result.stderr)
                    self.assertEqual(result.stdout, '')

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS enforcement')
    def test_invalid_grant_aborts_the_whole_launch_even_in_best_effort(self):
        dangling = str(Path(self.tmp.name) / 'dangling')
        os.symlink(self.a + '.missing', dangling)
        loop = str(Path(self.tmp.name) / 'loop')
        os.symlink(loop, loop)
        for bad in ('', self.a + '.missing', dangling, loop, '/' + 'x' * 5000):
            for mode in ([], ['--best-effort']):
                with self.subTest(bad=bad, mode=mode):
                    result = subprocess.run([JAIL, *mode, '--unix-socket', self.a,
                                             '--unix-socket', bad, '--', '/bin/sh', '-c',
                                             'echo SHOULD_NOT_RUN'],
                                            capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn('InvalidSocketPath', result.stderr)
                    self.assertEqual(result.stdout, '')

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS enforcement')
    def test_a_directory_grant_does_not_allow_its_socket_children(self):
        result = self.run_client(self.b, '--unix-socket', self.tmp.name)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Operation not permitted', result.stderr)

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS enforcement')
    def test_duplicate_reordered_and_large_allowlists_preserve_every_grant(self):
        # No application count cap: exercise repeated rules and a large profile.
        for i, paths in enumerate(([self.a, self.b], [self.b, self.a], [self.a] * 128 + [self.b])):
            flags = [arg for path in paths for arg in ('--unix-socket', path)]
            for path in (self.a, self.b):
                result = self.run_client(path, *flags)
                self.assertEqual(result.returncode, 0, result.stderr)
            foreign = self.listener(f'foreign-{i}')
            result = self.run_client(foreign, *flags)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Operation not permitted', result.stderr)

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS enforcement')
    def test_parallel_invocations_keep_independent_allowlists(self):
        def probe(own):
            other = self.b if own == self.a else self.a
            return (self.run_client(own, '--unix-socket', own),
                    self.run_client(other, '--unix-socket', own))
        with ThreadPoolExecutor(max_workers=4) as pool:
            for allowed, denied in pool.map(probe, [self.a, self.b] * 4):
                self.assertEqual(allowed.returncode, 0, allowed.stderr)
                self.assertNotEqual(denied.returncode, 0)
                self.assertIn('Operation not permitted', denied.stderr)

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS enforcement')
    def test_symlink_retargeting_after_launch_does_not_change_the_grant(self):
        alias = str(Path(self.tmp.name) / 'grant')
        os.symlink(self.a, alias)
        code = 'import socket,sys; print("READY",flush=True); input(); s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])'
        child = subprocess.Popen([JAIL, '--unix-socket', alias, '--', sys.executable,
                                  '-c', code, self.b], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            import select
            self.assertTrue(select.select([child.stdout], [], [], 10)[0], 'child did not start')
            self.assertEqual(child.stdout.readline().strip(), 'READY')
            os.unlink(alias)
            os.symlink(self.b, alias)
            _, stderr = child.communicate('\n', timeout=10)
            self.assertNotEqual(child.returncode, 0)
            self.assertIn('Operation not permitted', stderr)
        finally:
            if child.poll() is None:
                child.kill()
            child.communicate()

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux fallback contract')
    def test_unsupported_strict_refuses_best_effort_warns(self):
        strict = self.run_client(self.a, '--unix-socket', self.a)
        self.assertEqual(strict.returncode, 1, strict.stderr)
        self.assertIn('Unix socket connection restrictions are unavailable', strict.stderr)
        relaxed = self.run_client(self.b, '--best-effort', '--unix-socket', self.a)
        self.assertEqual(relaxed.returncode, 0, relaxed.stderr)
        self.assertIn('warning:', relaxed.stderr)
        self.assertIn('Unix socket connection restrictions are unavailable', relaxed.stderr)


if __name__ == '__main__':
    unittest.main()
