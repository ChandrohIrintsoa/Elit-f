import ast
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch, MagicMock

import elitf
import elitf_r2 as r2
from elitf_ui import ElitfUI, LogManager


class RepriseTests(unittest.TestCase):
    def test_docker_wrapper_arguments(self):
        with tempfile.TemporaryDirectory(prefix='elitf docker ') as d:
            root = Path(d)
            fake = root/'docker'
            fake.write_text('#!/usr/bin/env python3\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n')
            fake.chmod(0o755)
            source = root/'input.apk'
            source.touch()
            out = root/'out space'
            wrapper = Path(__file__).resolve().parents[1]/'docker/run.sh'
            result = subprocess.run(['bash', str(wrapper), str(source), str(out), '--no-analysis'], env={**os.environ, 'PATH': str(root)+os.pathsep+os.environ['PATH']}, check=True, capture_output=True, text=True)
            args = json.loads(result.stdout)
            self.assertEqual(args[args.index('--user')+1], f'{os.getuid()}:{os.getgid()}')
            self.assertIn(str(out)+':/app/output', args)
            self.assertEqual(args[-2:], ['--cli', '--no-analysis'])

    @unittest.skipUnless(os.getenv('ELITF_FMT_PREFIX'), 'set ELITF_FMT_PREFIX to a fmt CMake installation')
    def test_format_backend_cmake(self):
        project = Path(__file__).resolve().parents[1]
        cmake = (project/'CMakeLists.txt').read_text()
        check = cmake[cmake.index('include(CheckCXXSourceCompiles)'):cmake.index('find_package(${DARTLIB}')]
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root/'main.cpp').write_text('#include "Format.h"\n#include <iostream>\nint main(){std::cout << elitf_format::format("{}:{:#x}", "ok", 42);}\n')
            (root/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.20)\nproject(format_test LANGUAGES CXX)\nset(CMAKE_CXX_STANDARD 20)\n' + check + '\nadd_executable(smoke main.cpp)\ntarget_include_directories(smoke PRIVATE "' + str(project/'src') + '")\nif(NOT ELITF_HAS_STD_FORMAT)\ntarget_compile_definitions(smoke PRIVATE ELITF_USE_FMT)\ntarget_link_libraries(smoke PRIVATE fmt::fmt)\nendif()\n')
            subprocess.run(['cmake', '-S', str(root), '-B', str(root/'build'), '-DCMAKE_PREFIX_PATH='+os.environ['ELITF_FMT_PREFIX']], check=True, capture_output=True)
            subprocess.run(['cmake', '--build', str(root/'build')], check=True, capture_output=True)
            result = subprocess.run([str(root/'build/smoke')], check=True, capture_output=True, text=True)
            self.assertEqual(result.stdout, 'ok:0x2a')
            subprocess.run(['cmake', '-S', str(root), '-B', str(root/'build'), '-DELITF_HAS_STD_FORMAT=FALSE'], check=True, capture_output=True)
            subprocess.run(['cmake', '--build', str(root/'build')], check=True, capture_output=True)
            result = subprocess.run([str(root/'build/smoke')], check=True, capture_output=True, text=True)
            self.assertEqual(result.stdout, 'ok:0x2a')

    def test_export_menus_run_analysis(self):
        for choice in (3, 4):
            with self.subTest(choice=choice), tempfile.TemporaryDirectory() as d:
                ui = MagicMock()
                ui.console = None
                ui.get_choice.side_effect = [choice, 0]
                ui.run_with_live_display.side_effect = lambda title, steps, work: work(ui.log_mgr)
                with patch('builtins.input', side_effect=[d, d, '']), patch.object(elitf, 'check_dependencies', return_value=[]), patch.object(elitf, 'run_flutter_analysis') as analyze:
                    elitf.main_interactive(ui)
                analyze.assert_called_once()
                self.assertEqual(analyze.call_args.args[4], choice == 3)

    def test_batch_detects_zero_exit_errors(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            fake = root/'r2'
            fake.write_text('#!/bin/sh\necho "ERROR: broken command" >&2\nexit 0\n')
            fake.chmod(0o755)
            target = root/'input.so'
            target.touch()
            r2.generate_r2_scripts([{'path': str(target), 'name': target.name}], str(root/'out'))
            result = subprocess.run(['bash', str(root/'out/r2_analyze_all.sh')], env={**os.environ, 'PATH': str(root)+os.pathsep+os.environ['PATH']}, capture_output=True)
            self.assertEqual(result.returncode, 1)

    def test_plain_stream_burst_and_exception(self):
        ui = ElitfUI(force_plain=True)
        ui.console = None
        ui.log_mgr = LogManager(maxlen=3)
        def work(lm):
            for i in range(500):
                lm.add(f'message-{i:04d}')
            raise ValueError('worker failure')
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            with self.assertRaisesRegex(ValueError, 'worker failure'):
                ui.run_with_live_display('test', 1, work)
        for i in range(500):
            self.assertEqual(output.getvalue().count(f'message-{i:04d}'), 1)
        self.assertEqual(len(ui.log_mgr.logs), 3)
        self.assertIsNone(ui.log_mgr.pending)

    def test_export_text_cpp(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            source = root/'export.cpp'
            source.write_text(r"""#include "ExportText.h"
#include <iostream>
int main() {
    std::cout << IdaLabel("lib#\\\"name") << "\n";
    std::cout << PythonString("line1\ntriple ''' \\\" café") << "\n";
}
""")
            subprocess.run(['g++', '-std=c++20', '-I', str(Path(__file__).resolve().parents[1]/'src'), str(source), '-o', str(root/'export')], check=True)
            result = subprocess.run([str(root/'export')], check=True, capture_output=True, text=True)
            label, literal = result.stdout.splitlines()
            self.assertEqual(label, 'lib___name')
            self.assertEqual(ast.literal_eval(literal), "line1\ntriple ''' \\\" café")

    def test_full_execution_uses_same_rendering(self):
        with tempfile.TemporaryDirectory(prefix='elitf space ') as d:
            target = Path(d) / 'input.so'
            target.touch()
            targets = [{'path': str(target), 'name': target.name}]
            generated = r2.generate_r2_scripts(targets, str(Path(d)/'generated'))
            with patch.object(r2, '_find_r2', return_value='/fake/r2'), patch.object(r2, '_run_single_r2', return_value=True):
                executed = r2.run_r2_scripts(targets, str(Path(d)/'executed'))
            self.assertEqual(Path(generated[0]).read_text(), Path(executed[0]).read_text())

    def test_r2_working_directory(self):
        with tempfile.TemporaryDirectory() as d:
            script = str(Path(d)/'commands.r2')
            with patch.object(r2.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')) as run:
                self.assertTrue(r2._run_single_r2('/fake/r2', script, '/tmp/input.so', 5, None, 'input'))
            self.assertEqual(run.call_args.kwargs['cwd'], d)

    @unittest.skipUnless(shutil.which('r2'), 'real radare2 unavailable')
    def test_real_r2_presets_and_batch(self):
        with tempfile.TemporaryDirectory(prefix='elitf space ') as d:
            root = Path(d)
            source = root/'sample.c'
            source.write_text('const char *marker="elitf-marker"; int example(int x){return x+7;}')
            target = root/'sample.so'
            subprocess.run(['gcc', '-shared', '-fPIC', str(source), '-o', str(target)], check=True)
            targets = [{'path': str(target), 'name': target.name}]
            for key in ('minimal', 'quick', 'standard', 'full'):
                with self.subTest(preset=key):
                    preset = r2.R2_PRESETS[key]
                    output = root/key
                    r2.run_r2_custom(targets, str(output), preset['analysis_key'], preset['extraction_keys'])
                    files = list((output/'r2_output').glob('*functions_json.txt'))
                    self.assertEqual(len(files), 1)
                    funcs = json.loads(files[0].read_text())
                    self.assertTrue(any('example' in f.get('name', '') for f in funcs))
            output = root/'batch'
            r2.generate_r2_scripts(targets, str(output))
            result = subprocess.run(['bash', str(output/'r2_analyze_all.sh')], capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('ERROR:', result.stderr)
            self.assertTrue(list((output/'r2_output').glob('*functions_json.txt')))
            disassembly = list((output/'r2_output').glob('*disassembly.txt'))
            self.assertEqual(len(disassembly), 1)
            self.assertIn('example', disassembly[0].read_text())


if __name__ == '__main__':
    unittest.main()
