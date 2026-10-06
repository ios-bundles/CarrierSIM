"""Offline regression tests: temporary files and mocked device boundaries only."""
import asyncio
import contextlib
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import carrier
import launch
from carriersim_version import VERSION


class LinuxBackendTest(unittest.TestCase):
    def test_dispatcher_keeps_apple_backend_on_macos_and_windows(self):
        self.assertEqual(carrier.host_backend('darwin'), 'apple')
        self.assertEqual(carrier.host_backend('win32'), 'apple')
        self.assertEqual(carrier.host_backend('linux'), 'linux-native-atc')
        with self.assertRaises(RuntimeError):
            carrier.host_backend('freebsd')

    def test_apple_worker_rejects_linux_probe(self):
        with patch.object(carrier, 'host_backend', return_value='apple'), \
             patch('airtraffic_apple.run_worker') as apple:
            with self.assertRaisesRegex(RuntimeError, 'только на Linux'):
                carrier.host_worker({'probe': True})
            apple.assert_not_called()

    def test_distribution_description_falls_back_without_os_release(self):
        with patch('platform.freedesktop_os_release', return_value={'PRETTY_NAME': 'ALT Regular'}), \
             patch('platform.platform', return_value='Linux-6.18'), \
             patch('platform.machine', return_value='x86_64'):
            self.assertEqual(carrier.linux_platform_description(), 'ALT Regular · Linux-6.18 · x86_64')
        with patch('platform.freedesktop_os_release', side_effect=OSError), \
             patch('platform.platform', return_value='Linux-6.18'), \
             patch('platform.machine', return_value='x86_64'):
            self.assertEqual(carrier.linux_platform_description(), 'Linux-6.18 · x86_64')

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux-only usbmuxd paths')
    def test_usbmuxd_detects_sbin_without_path(self):
        with patch('shutil.which', return_value=None), \
             patch.object(carrier.Path, 'is_file', return_value=True), \
             patch.object(carrier.os, 'access', return_value=True), \
             patch.object(carrier.Path, 'stat', side_effect=OSError):
            self.assertIn('/usr/sbin/usbmuxd', carrier.linux_usbmuxd_status())

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux-only usbmuxd paths')
    def test_linux_usbmuxd_reports_missing(self):
        with patch('shutil.which', return_value=None), \
             patch.object(carrier.Path, 'is_file', return_value=False), \
             patch.object(carrier.Path, 'stat', side_effect=OSError):
            self.assertEqual(carrier.linux_usbmuxd_status(), 'не найден')


class HostSessionTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run = pathlib.Path(self.temp.name)

    async def test_callback_authorizes_final_asset_and_connection_is_saved(self):
        child = (
            "import json,sys,pathlib; "
            "config=json.loads(pathlib.Path(sys.argv[1]).read_text()); "
            "print('CARRIER_SWAP_JSON:'+json.dumps({'event':'before-final-asset'}),flush=True); "
            "line=sys.stdin.readline().strip(); "
            "print('CARRIER_SWAP_JSON:'+json.dumps({'ok':line=='CONTINUE','connection':config['connection']}),flush=True)"
        )
        calls = []
        async def callback():
            calls.append('backup')
            self.assertTrue((self.run/'host-input.json').exists())
        with patch.object(carrier, 'host_command', return_value=[sys.executable, '-c', child]), \
             patch.object(carrier, 'CONNECTION', 'Network'):
            await carrier.host_session('device', [('a', 'b')], callback, self.run)
        self.assertEqual(calls, ['backup'])
        self.assertFalse((self.run/'host-input.json').exists())
        log = (self.run/'host.jsonl').read_text()
        self.assertIn('"connection": "Network"', log)

    async def test_failed_callback_never_authorizes(self):
        child = (
            "import json,sys; "
            "print('CARRIER_SWAP_JSON:'+json.dumps({'event':'before-final-asset'}),flush=True); "
            "line=sys.stdin.readline(); "
            "print('CARRIER_SWAP_JSON:'+json.dumps({'ok':False,'line':line}),flush=True)"
        )
        async def callback():
            raise RuntimeError('backup failed')
        with patch.object(carrier, 'host_command', return_value=[sys.executable, '-c', child]):
            with self.assertRaisesRegex(RuntimeError, 'backup failed'):
                await carrier.host_session('device', [('a', 'b')], callback, self.run)
        self.assertFalse((self.run/'host-input.json').exists())


class FilesTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)

    def test_run_details_reads_linux_manifest_counts(self):
        stage = self.root / 'restore'
        stage.mkdir()
        carrier.save_json(stage / 'journal.json', {'phase': 'final-authorized', 'complete': False})
        (stage / 'host.jsonl').write_text(
            'CARRIER_SWAP_JSON:' + json.dumps({'event': 'manifest', 'expected': 3, 'matched': 3}) + '\n'
            'CARRIER_SWAP_JSON:' + json.dumps({'ok': False, 'error': 'sync failed'}) + '\n', encoding='utf-8')
        rows = carrier.run_details(self.root)
        self.assertIn(('  Ответ AirTraffic', 'ожидалось 3, найдено 3, повторяется 0'), rows)
        self.assertIn(('  Ошибка AirTraffic', 'sync failed'), rows)

    def test_backup_roundtrip_preserves_files_directories_and_links(self):
        tree = {'bundle': ('d', b''), 'bundle/data': ('f', b'\x00\xff'),
                'alias': ('l', b'bundle'), 'empty': ('d', b'')}
        path = self.root / 'backup.zip'
        carrier.write_tree_zip(path, tree)
        self.assertEqual(carrier.read_tree_zip(path), tree)
        with self.assertRaises(FileExistsError):
            carrier.write_tree_zip(path, tree)

    def test_archive_rejects_path_traversal(self):
        for name in ('../outside', '/absolute', 'a/../b', 'a\\b', 'a//b', './x'):
            with self.subTest(name=name):
                path = self.root / 'bad.zip'
                with zipfile.ZipFile(path, 'w') as archive:
                    archive.writestr(name, b'bad')
                with self.assertRaises(RuntimeError):
                    carrier.read_tree_zip(path)

    def test_tree_rejects_invalid_parents_and_links(self):
        for tree in ({'missing/file': ('f', b'x')}, {'a': ('f', b'x'), 'a/b': ('f', b'y')},
                     {'link': ('l', b'a\x00b')}, {'x': ('unknown', b'')}):
            with self.subTest(tree=tree), self.assertRaises(RuntimeError):
                carrier.validate_tree(tree)

    def test_tree_limits(self):
        with patch.object(carrier, 'MAX_BYTES', 1), self.assertRaises(RuntimeError):
            carrier.validate_tree({'file': ('f', b'xx')})
        with patch.object(carrier, 'MAX_NODES', 0), self.assertRaises(RuntimeError):
            carrier.validate_tree({'empty': ('d', b'')})

    def test_hash_ignores_order_but_detects_content_and_type(self):
        tree = {'a': ('f', b'x'), 'b': ('f', b'y')}
        self.assertEqual(carrier.tree_hash(tree), carrier.tree_hash(dict(reversed(list(tree.items())))))
        for changed in ({'a': ('f', b'z'), 'b': ('f', b'y')}, {'a': ('l', b'x'), 'b': ('f', b'y')}):
            self.assertNotEqual(carrier.tree_hash(tree), carrier.tree_hash(changed))

    def test_json_is_utf8_and_replaces_existing_file(self):
        path = self.root / 'journal.json'
        carrier.save_json(path, {'message': 'Сохранено'})
        carrier.save_json(path, {'message': 'Обновлено'})
        self.assertEqual(carrier.read_json(path), {'message': 'Обновлено'})
        self.assertFalse(path.with_suffix('.json.tmp').exists())

    def test_bundled_assets_have_expected_digest_and_valid_tree(self):
        self.assertTrue(carrier.load_assets())

    def test_config_resolves_operator_then_default(self):
        path = self.root / 'bundle.yaml'
        path.write_text('\ufeff# comment\ndefault: Swisscom_ch\n"25001": "O2_Germany.bundle" # note\n', encoding='utf-8')
        config = carrier.load_bundle_config(path)
        self.assertEqual(carrier.bundle_for('25001', config), 'O2_Germany.bundle')
        self.assertEqual(carrier.bundle_for('25701', config), 'Swisscom_ch.bundle')
        self.assertEqual(carrier.load_bundle_config(self.root / 'missing'), {'default': carrier.BUNDLE})

    def test_config_rejects_duplicates_and_invalid_names(self):
        for value in ('default: ../bad', 'default: One\ndefault: Two', '250: One', 'invalid YAML'):
            with self.subTest(value=value):
                path = self.root / 'bundle.yaml'
                path.write_text(value, encoding='utf-8')
                with self.assertRaises(RuntimeError):
                    carrier.load_bundle_config(path)

    def test_pending_filters_by_phone_and_recovery_state(self):
        def journal(stage, **values):
            folder = self.root / '20260101-run' / stage
            folder.mkdir(parents=True)
            carrier.save_json(folder / 'journal.json', values)
            return folder
        wanted = journal('pending', udid_hash=carrier.digest(b'phone'), requires_recovery=True)
        journal('other', udid_hash=carrier.digest(b'other'), requires_recovery=True)
        journal('done', udid_hash=carrier.digest(b'phone'), requires_recovery=True, recovered_by='recovery')
        self.assertEqual(carrier.pending(self.root, 'phone'), [wanted])

    def test_operation_lock_can_be_reused_without_growing_file(self):
        for _ in range(3):
            with carrier.operation_lock(self.root):
                self.assertEqual((self.root / '.lock').stat().st_size, 1)

    def test_commcenter_report_requires_correct_slot_and_signature(self):
        path = self.root / 'syslog.txt'
        path.write_text(carrier.BUNDLE_BLOCK + '\nResolved path: /System/Other.bundle\n'
                        'Linking Path: /Carrier1Bundle.bundle\nVerification Result: Failed\n'
                        + carrier.BUNDLE_BLOCK + '\nResolved path: /System/O2_Germany.bundle\n'
                        'Linking Path: /Carrier2Bundle.bundle\nVerification Result: Success\n', encoding='utf-8')
        sims = [{'slot': 'kOne', 'plmn': '25001', 'bundle': 'Swisscom_ch.bundle'},
                {'slot': 'kTwo', 'plmn': '25002', 'bundle': 'O2_Germany.bundle'}]
        result = carrier.report_log(path, sims)
        self.assertFalse(result[0]['verified'])
        self.assertTrue(result[1]['verified'])
        self.assertEqual(result[1]['selected'], 'O2_Germany.bundle')


class SimsTest(unittest.TestCase):
    def setUp(self):
        self.rows = [dict(Slot='kOne', MCC='250', MNC='01', InternationalMobileSubscriberIdentity='250011234567890'),
                     dict(Slot='kTwo', MCC='250', MNC='02', InternationalMobileSubscriberIdentity='250029876543210')]

    def test_selected_sim_uses_its_operator_profile(self):
        result = carrier.select_sims(self.rows, {'25002': 'O2_Germany.bundle'}, ('kTwo',))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['bundle'], 'O2_Germany.bundle')
        self.assertEqual(result[0]['imsi'], self.rows[1]['InternationalMobileSubscriberIdentity'])

    def test_rejects_missing_selected_sim_duplicate_slot_and_invalid_imsi(self):
        cases = ([self.rows[0]], [self.rows[0], self.rows[0]],
                 [dict(self.rows[1], InternationalMobileSubscriberIdentity='123')],
                 [dict(self.rows[1], InternationalMobileSubscriberIdentity='257029876543210')])
        for rows in cases:
            with self.subTest(rows=rows), self.assertRaises(RuntimeError):
                carrier.select_sims(rows, slots=('kTwo',))

    def test_unselected_sim_without_imsi_does_not_block_selected_sim(self):
        self.rows[1].pop('InternationalMobileSubscriberIdentity')
        self.assertEqual(len(carrier.select_sims(self.rows, slots=('kOne',))), 1)

    def test_default_profile_skips_foreign_sim_unless_named_or_picked(self):
        foreign = dict(Slot='kTwo', MCC='262', MNC='01')  # no IMSI needed for a SIM left alone
        config = {'default': 'Vodafone_hu.bundle'}
        skipped = []
        result = carrier.select_sims([self.rows[0], foreign], config, any_mcc=False, skipped=skipped)
        self.assertEqual([s['slot'] for s in result], ['kOne'])
        self.assertEqual(skipped, ['kTwo'])
        foreign['InternationalMobileSubscriberIdentity'] = '262011234567890'
        named = carrier.select_sims([foreign], dict(config, **{'26201': 'O2_Germany.bundle'}), any_mcc=False)
        self.assertEqual(named[0]['bundle'], 'O2_Germany.bundle')
        picked = carrier.select_sims([foreign], config, ('kTwo',), any_mcc=True)
        self.assertEqual(picked[0]['bundle'], 'Vodafone_hu.bundle')
        with self.assertRaises(RuntimeError):
            carrier.select_sims([foreign], config, any_mcc=False, skipped=[])
        status_skipped = []  # --status only reads: the plan still shows "не трогаю"
        self.assertEqual(carrier.select_sims([foreign], config, any_mcc=False, skipped=status_skipped,
                                             only_skipped_ok=True), [])
        self.assertEqual(status_skipped, ['kTwo'])
        self.assertEqual(carrier.bundle_for('25701', config), 'Vodafone_hu.bundle')
        blank = dict(Slot='kOne', MCC='', MNC='')  # locked phone: not a foreign SIM, an error
        with self.assertRaisesRegex(RuntimeError, 'разблокируйте'):
            carrier.select_sims([blank], config, any_mcc=False, skipped=[])

    def test_plan_changes_only_selected_imsi_and_preserves_original(self):
        original = {'25001': ('l', b'existing'), 'Info.plist': ('f', b'data')}
        sims = carrier.select_sims(self.rows, slots=('kTwo',))
        desired = carrier.make_plan(original, sims)
        self.assertEqual(desired['25001'], original['25001'])
        self.assertEqual(desired['Info.plist'], original['Info.plist'])
        self.assertNotIn(sims[0]['imsi'], original)
        self.assertEqual(desired[sims[0]['imsi']], carrier.bundle_link(carrier.BUNDLE))

    def test_plan_does_not_overwrite_a_regular_file(self):
        sims = carrier.select_sims(self.rows, slots=('kOne',))
        with self.assertRaises(RuntimeError):
            carrier.make_plan({sims[0]['imsi']: ('f', b'keep')}, sims)

    def test_restore_selected_sim_keeps_other_sim_and_non_imsi_nodes(self):
        a, b = [row['InternationalMobileSubscriberIdentity'] for row in self.rows]
        tree = {a: ('l', b'first'), b: ('l', b'second'), '25001': ('l', b'operator'),
                '123456789012345': ('f', b'keep')}
        restored = carrier.remove_imsi_links(tree, only={a})
        self.assertEqual(restored, {k: v for k, v in tree.items() if k != a})
        self.assertEqual(carrier.remove_imsi_links(tree), {k: v for k, v in tree.items() if k not in (a, b)})

    def test_masks_phone_and_identifiers_in_logs(self):
        masked = carrier.mask_phone('+7 (999) 123-45-67')
        self.assertIn('4567', masked)
        self.assertNotIn('999', masked)
        self.assertEqual(carrier.mask_phone(None), 'номер недоступен')
        self.assertNotIn('250011234567890', carrier.mask_log('IMSI 250011234567890'))

    def test_syslog_capture_masks_identifiers_before_disk(self):
        rows = [b'Oct  3 02:33:42 Ivan-Petrov-iPhone CommCenter[109] <Notice>: Returning bundle match: Matches: '
                b'[Name: /var/mobile/Library/Carrier Bundles/iPhone/250019999999999, Score: 59.00]',
                b'Oct  3 02:33:42 Ivan-Petrov-iPhone CommCenter[109] <Notice>: persona:89701012345678901234 '
                b'old link 257029876543210 tel +7 (999) 123-45-67 at 2026-09-30 16:04:55+0300',
                b'Oct  3 02:33:42 Ivan-Petrov-iPhone CommCenter[109] <Notice>: Frequency: 955000000, '
                b'bands 0x00ff12345678901234ff, ../airlift-src-ce9b03ba8772252928d2/q0',
                b'Oct  3 02:33:42 Ivan-Petrov-iPhone wifid[50] <Notice>: 250019999999999']
        class Syslog:
            def __init__(self, device): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *exc): return False
            async def watch(self):
                for row in rows: yield row
                written.set()
                await asyncio.Event().wait()
        async def run(path):
            nonlocal written
            written = asyncio.Event()
            async with carrier.syslog_capture(None, path, lambda line: 'CommCenter' in line, linger=0):
                await asyncio.wait_for(written.wait(), 5)
        written = None
        rows_device = [dict(Slot='kOne', InternationalMobileSubscriberIdentity='250019999999999',
                            IntegratedCircuitCardIdentity='89701012345678901234')]
        device = SimpleNamespace(get_value=AsyncMock(return_value=rows_device))
        with tempfile.TemporaryDirectory() as root, \
                patch.dict(carrier.LOG_SECRETS, clear=True), \
                patch('pymobiledevice3.services.syslog.SyslogService', Syslog):
            asyncio.run(carrier.carrier_rows(device))
            path = pathlib.Path(root) / 'commcenter.log'
            asyncio.run(run(path))
            text = path.read_text(encoding='utf-8')
        self.assertIn('Carrier Bundles/iPhone/<imsi>, Score: 59.00', text)
        self.assertIn('persona:<iccid> old link <num> tel <num> at 2026-09-30 16:04:55+0300', text)
        self.assertIn('Frequency: 955000000, bands 0x00ff12345678901234ff, ../airlift-src-ce9b03ba8772252928d2/q0',
                      text)
        self.assertIn('Oct  3 02:33:42 iPhone CommCenter[109]', text)
        for secret in ('250019999999999', '257029876543210', '8970101', 'Ivan', '999) 123'):
            self.assertNotIn(secret, text)
        self.assertNotIn('wifid', text)

    def test_codec_answer_is_not_confused_with_offer(self):
        answer = 'm=audio 100 RTP/AVP 96 101\na=rtpmap:96 EVS/16000\na=rtpmap:101 telephone-event/8000'
        self.assertEqual(carrier.sip_answer_codec(answer), 'EVS/16000')
        self.assertIsNone(carrier.sip_answer_codec(answer.replace('96 101', '96 97 101') + '\na=rtpmap:97 AMR/8000'))


class BooksRestoreTest(unittest.IsolatedAsyncioTestCase):
    async def test_unchanged_books_file_is_not_opened_for_writing(self):
        afc = SimpleNamespace(get_file_contents=AsyncMock(return_value=b'original'),
                              set_file_contents=AsyncMock(), makedirs=AsyncMock())
        tree = {'Books.plist': ('f', b'original')}
        async def exists(_, path):
            if path == 'Books':
                return {'st_ifmt': 'S_IFDIR'}
            if path == 'Books/Books.plist':
                return {'st_ifmt': 'S_IFREG', 'st_size': 8}
            return None
        with patch.object(carrier, 'exists', exists), \
             patch.object(carrier, 'read_managed_books', AsyncMock(return_value=(True, tree))):
            self.assertEqual(await carrier.restore_books(afc, tree, True), [])
        afc.set_file_contents.assert_not_awaited()
        afc.makedirs.assert_not_awaited()

    async def test_missing_empty_managed_folder_is_recreated(self):
        state = {'Books': ('d', b'')}
        async def exists(_, path):
            return {'st_ifmt': 'S_IFDIR'} if path in state else None
        async def makedirs(path):
            state[path] = ('d', b'')
        async def read_managed(_):
            return True, {path.removeprefix('Books/'): value for path, value in state.items() if path != 'Books'}
        afc = SimpleNamespace(makedirs=AsyncMock(side_effect=makedirs))
        with patch.object(carrier, 'exists', exists), patch.object(carrier, 'read_managed_books', read_managed):
            self.assertEqual(await carrier.restore_books(afc, {'Managed': ('d', b'')}, True), [])
        afc.makedirs.assert_awaited_once_with('Books/Managed')
        self.assertIn('Books/Managed', state)

    async def test_unexpected_restored_contents_raise_instead_of_reporting_success(self):
        afc = SimpleNamespace()
        async def exists(_, path):
            return {'st_ifmt': 'S_IFDIR'} if path == 'Books' else None
        with patch.object(carrier, 'exists', exists), \
             patch.object(carrier, 'read_managed_books', AsyncMock(return_value=(True, {'Books.plist': ('f', b'unexpected')}))):
            with self.assertRaisesRegex(RuntimeError, 'Books'):
                await carrier.restore_books(afc, {}, True)


class RetryTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.args = SimpleNamespace(udid=None, wait_seconds=1, diagnose=False, watch_call=False, report=False,
                                    attempts=2, runs=self.root, status=False, recover=False)

    async def run_case(self, error, before, after):
        device = SimpleNamespace(close=AsyncMock())
        with patch.object(carrier, 'choose_device', AsyncMock(return_value='phone')), \
             patch.object(carrier, 'pending', side_effect=[before, after]), \
             patch.object(carrier, 'execute', AsyncMock(side_effect=error)), \
             patch.object(carrier, 'ready_device', AsyncMock(return_value=device)) as ready, \
             patch.object(carrier, 'recover_all', AsyncMock()) as recover, \
             patch.object(carrier, 'save_environment'), \
             patch.object(carrier, 'transient_error', return_value=False), \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(type(error)):
                await carrier.execute_with_retry(self.args, {})
            return ready, recover, device

    async def test_status_failure_never_recovers_or_writes(self):
        self.args.status = True
        ready, recover, device = await self.run_case(RuntimeError('failed'), [], [self.root / 'stage'])
        ready.assert_not_awaited()
        recover.assert_not_awaited()
        device.close.assert_not_awaited()

    async def test_failure_does_not_recover_an_older_stage(self):
        old = self.root / 'old'
        ready, recover, _ = await self.run_case(RuntimeError('failed'), [old], [old])
        ready.assert_not_awaited()
        recover.assert_not_awaited()

    async def test_failure_recovers_only_new_stage_and_closes_device(self):
        old, new = self.root / 'old', self.root / 'new'
        _, recover, device = await self.run_case(RuntimeError('failed'), [old], [old, new])
        self.assertEqual(recover.await_args.args[1], [new])
        device.close.assert_awaited_once()

    async def test_read_only_diagnostics_bypasses_install_and_recovery(self):
        self.args.diagnose = True
        with patch.object(carrier, 'choose_device', AsyncMock(return_value='phone')), \
             patch.object(carrier, 'diagnostics', AsyncMock(return_value=0)), \
             patch.object(carrier, 'execute', AsyncMock()) as execute, \
             patch.object(carrier, 'recover_all', AsyncMock()) as recover:
            self.assertEqual(await carrier.execute_with_retry(self.args, {}), 0)
            execute.assert_not_awaited()
            recover.assert_not_awaited()

    async def test_transient_failure_retries_same_phone(self):
        with patch.object(carrier, 'choose_device', AsyncMock(return_value='phone')) as choose, \
             patch.object(carrier, 'pending', return_value=[]), \
             patch.object(carrier, 'execute', AsyncMock(side_effect=[TimeoutError(), 0])) as execute, \
             patch.object(carrier, 'transient_error', return_value=True), \
             patch.object(carrier.asyncio, 'sleep', AsyncMock()), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(await carrier.execute_with_retry(self.args, {}), 0)
            self.assertEqual(execute.await_count, 2)
            choose.assert_awaited_once()
            self.assertEqual(self.args.udid, 'phone')


class ReportTest(unittest.IsolatedAsyncioTestCase):
    ROWS = [dict(Slot='kOne', MCC='250', MNC='01', CFBundleIdentifier='com.apple.Vodafone_tr', CFBundleVersion='72.0.1',
                 InternationalMobileSubscriberIdentity='250011234567890', IntegratedCircuitCardIdentity='8970101234567890123')]

    def test_answers_are_normalised_and_masked(self):
        self.assertEqual(carrier.report_answer(''), 'не проверял')
        self.assertEqual(carrier.report_answer(' Д '), 'да')
        self.assertEqual(carrier.report_answer('n'), 'нет')
        self.assertNotIn('9161234567', carrier.report_answer('звонил на +7 916 123-45-67'))

    async def test_report_has_bundle_and_answers_but_no_identifiers(self):
        answers = iter(['д', 'н', '', 'n1', 'д', '', '', '', 'Москва'])
        with tempfile.TemporaryDirectory() as runs, \
                patch.object(carrier, 'commcenter_stream', AsyncMock()), \
                patch.object(carrier.sys.stdin, 'isatty', return_value=True), \
                patch('builtins.input', lambda *_: next(answers)), \
                patch.dict(carrier.DIAG, {'info': {'ProductType': 'iPhone18,1', 'ProductVersion': '27.0.1',
                                                   'BuildVersion': '24A446'}}), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            args = SimpleNamespace(runs=pathlib.Path(runs), seconds=10)
            self.assertEqual(await carrier.run_report(None, args, self.ROWS), 0)
            saved = next(pathlib.Path(runs).glob('*-report/report.txt')).read_text(encoding='utf-8')
        self.assertIn(saved.strip(), output.getvalue())
        for expected in ('iPhone 17 Pro', 'МТС (250-01)', 'Vodafone_tr 72.0.1', 'в авиарежиме по Wi-Fi проходит: да',
                         'включается сам, без авиарежима: нет', '5G: полоса n в *3001#12345#*: n1', 'Москва'):
            self.assertIn(expected, saved)
        for secret in ('250011234567890', '8970101234567890123'):
            self.assertNotIn(secret, saved)

    async def run_with(self, answers):
        def answer(*_):
            item = next(answers)
            if isinstance(item, BaseException): raise item
            return item
        with tempfile.TemporaryDirectory() as runs, \
                patch.object(carrier, 'commcenter_stream', AsyncMock()), \
                patch.object(carrier.sys.stdin, 'isatty', return_value=True), \
                patch('builtins.input', answer), \
                patch.dict(carrier.DIAG, {'info': {'ProductType': 'iPhone18,1'}}), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(await carrier.run_report(None, SimpleNamespace(runs=pathlib.Path(runs), seconds=10), self.ROWS), 0)
            return next(pathlib.Path(runs).glob('*-report/report.txt')).read_text(encoding='utf-8')

    async def test_region_is_free_text_not_a_yes_no_answer(self):
        saved = await self.run_with(iter([''] * 8 + ['н']))
        self.assertIn(' · н', saved)

    async def test_interrupted_questions_still_save_the_report(self):
        for stop in (EOFError(), KeyboardInterrupt()):
            saved = await self.run_with(iter(['д', stop]))
            self.assertIn('вопросы прерваны', saved)
            self.assertIn('Журнал CommCenter', saved)
            self.assertIn('в авиарежиме по Wi-Fi проходит: да', saved)  # the interrupted SIM keeps its answer

    async def test_ctrl_c_interrupts_the_question_itself(self):
        # Under asyncio.run the first Ctrl-C only cancels the task; while asking it must reach input().
        import signal
        handlers = []
        def answer(*_):
            handlers.append(signal.getsignal(signal.SIGINT)); return ''
        previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
        try:
            with tempfile.TemporaryDirectory() as runs, \
                    patch.object(carrier, 'commcenter_stream', AsyncMock()), \
                    patch.object(carrier.sys.stdin, 'isatty', return_value=True), \
                    patch('builtins.input', answer), \
                    patch.dict(carrier.DIAG, {'info': {'ProductType': 'iPhone18,1'}}), \
                    contextlib.redirect_stdout(io.StringIO()):
                await carrier.run_report(None, SimpleNamespace(runs=pathlib.Path(runs), seconds=10), self.ROWS)
            after = signal.getsignal(signal.SIGINT)
        finally:
            signal.signal(signal.SIGINT, previous)
        self.assertTrue(handlers)
        self.assertTrue(all(h is signal.default_int_handler for h in handlers))
        self.assertIs(after, signal.SIG_IGN)  # the caller's handler is back after the questions


class ReportNoTtyTest(unittest.IsolatedAsyncioTestCase):
    async def test_without_a_terminal_the_report_says_questions_were_skipped(self):
        rows = [dict(Slot='kOne', MCC='250', MNC='02', CFBundleIdentifier='com.apple.MTS_ua', CFBundleVersion='72.0')]
        with tempfile.TemporaryDirectory() as runs, \
                patch.object(carrier, 'commcenter_stream', AsyncMock()), \
                patch.object(carrier.sys.stdin, 'isatty', return_value=False), \
                patch('builtins.input', side_effect=AssertionError('must not ask')), \
                patch.dict(carrier.DIAG, {'info': {'ProductType': 'iPhone17,2'}}), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            await carrier.run_report(None, SimpleNamespace(runs=pathlib.Path(runs), seconds=10), rows)
            saved = next(pathlib.Path(runs).glob('*-report/report.txt')).read_text(encoding='utf-8')
        self.assertIn('Ручные проверки: не заданы', saved)
        self.assertIn('пункт 11 из меню', output.getvalue())

    async def test_terminal_without_sim_slots_does_not_blame_the_terminal(self):
        with tempfile.TemporaryDirectory() as runs, \
                patch.object(carrier, 'commcenter_stream', AsyncMock()), \
                patch.object(carrier.sys.stdin, 'isatty', return_value=True), \
                patch('builtins.input', return_value=''), \
                patch.dict(carrier.DIAG, {'info': {'ProductType': 'iPhone17,2'}}), \
                contextlib.redirect_stdout(io.StringIO()):
            await carrier.run_report(None, SimpleNamespace(runs=pathlib.Path(runs), seconds=10), [dict(MCC='250')])
            saved = next(pathlib.Path(runs).glob('*-report/report.txt')).read_text(encoding='utf-8')
        self.assertNotIn('без терминала', saved)


class LogStreamTest(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def entry(text, filename='/System/Library/Frameworks/CoreTelephony.framework/Support/CommCenter'):
        return SimpleNamespace(message=text, label=None, filename=filename,
                               timestamp=__import__('datetime').datetime(2026, 9, 30))

    async def collect(self, plan, seconds=0.5, pids=None, on_entry=None, stop=None):
        # plan: one item per syslog() call — a list of texts (or (text, filename)), optionally ending in an exception.
        # pids: one item per get_pid_list() call — True, False (no CommCenter) or an exception to raise.
        plan = list(plan); pids = list(pids or []); seen = []; self.syslog_pids = []

        test = self

        class FakeTrace:
            def __init__(self, device): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            async def get_pid_list(self):
                found = pids.pop(0) if pids else True
                if isinstance(found, BaseException): raise found
                return {'Payload': {'42': {'ProcessName': 'CommCenter'}} if found else {}}
            async def syslog(self, pid):
                test.syslog_pids.append(pid)
                step = plan.pop(0) if plan else []
                for item in step:
                    if isinstance(item, BaseException): raise item
                    yield LogStreamTest.entry(*item) if isinstance(item, tuple) else LogStreamTest.entry(item)
                await asyncio.Event().wait()

        with tempfile.TemporaryDirectory() as directory, \
                patch('pymobiledevice3.services.os_trace.OsTraceService', FakeTrace), \
                patch.object(carrier.asyncio, 'sleep', AsyncMock()), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            await carrier.commcenter_stream(None, seconds, pathlib.Path(directory, 'log'),
                                            on_entry or (lambda e, msg: seen.append(msg)), stop=stop)
        return seen, output.getvalue()

    async def test_drop_then_reconnect_counts_one_reconnect(self):
        from pymobiledevice3.exceptions import ConnectionTerminatedError
        seen, out = await self.collect([['before', ConnectionTerminatedError()], ['after']])
        self.assertEqual(seen, ['before', 'after'])
        self.assertIn('переподключений: 1', out)

    async def test_socket_timeout_is_a_drop_not_the_end(self):
        seen, out = await self.collect([['before', TimeoutError(60, 'Operation timed out')], ['after']])
        self.assertEqual(seen, ['before', 'after'])

    async def test_missing_commcenter_on_reconnect_is_retried(self):
        from pymobiledevice3.exceptions import ConnectionTerminatedError
        # pids: initial lookup, then "not running yet", then found again.
        seen, out = await self.collect([['before', ConnectionTerminatedError()], ['after']], pids=[True, False, True])
        self.assertEqual(seen, ['before', 'after'])

    async def test_process_list_refused_over_wifi_streams_all_and_keeps_commcenter(self):
        from pymobiledevice3.exceptions import ConnectionTerminatedError
        seen, out = await self.collect([['before', ('noise', '/usr/libexec/locationd'), ConnectionTerminatedError()],
                                        ['after']], pids=[ConnectionTerminatedError()])
        self.assertEqual(seen, ['before', 'after'])
        # The refused list is not asked for again on reconnect: both streams are unfiltered.
        self.assertEqual(self.syslog_pids, [carrier.ALL_PROCESSES] * 2)
        self.assertIn('переподключений: 1', out)

    async def test_refused_lookup_on_reconnect_is_a_drop_not_the_wifi_fallback(self):
        from pymobiledevice3.exceptions import ConnectionTerminatedError
        # Cable, airplane mode: the relay is still down when the pid is looked up again.
        seen, out = await self.collect([['before', ConnectionTerminatedError()], ['after']],
                                       pids=[True, ConnectionTerminatedError(), True])
        self.assertEqual(seen, ['before', 'after'])
        self.assertEqual(self.syslog_pids, [42, 42])
        self.assertNotIn('список процессов', out)

    async def test_fatal_error_is_not_swallowed(self):
        from pymobiledevice3.exceptions import NotPairedError
        with self.assertRaises(NotPairedError):
            await self.collect([['before', NotPairedError()]])

    async def test_log_that_never_came_is_an_error(self):
        from pymobiledevice3.exceptions import ConnectionFailedError
        with patch.object(carrier, 'LOG_RECONNECT_SECONDS', 0.05), self.assertRaisesRegex(RuntimeError, 'недоступен'):
            await self.collect([[ConnectionFailedError()]] * 10000, seconds=5)

    async def test_log_that_never_returns_keeps_what_was_collected(self):
        from pymobiledevice3.exceptions import ConnectionFailedError
        with patch.object(carrier, 'LOG_RECONNECT_SECONDS', 0.05):
            seen, output = await self.collect([['before', ConnectionFailedError()]] + [[ConnectionFailedError()]] * 10000,
                                              seconds=5)
        self.assertEqual(seen, ['before'])
        self.assertIn('Журнал не вернулся за 0.05 с', output)

    async def test_hung_reconnect_is_bounded_and_keeps_what_was_collected(self):
        from pymobiledevice3.exceptions import ConnectionFailedError
        with patch.object(carrier, 'LOG_RECONNECT_SECONDS', 0.05):
            seen, output = await self.collect([['before', ConnectionFailedError()], []], seconds=30)
        self.assertEqual(seen, ['before'])
        self.assertIn('Журнал не вернулся за 0.05 с', output)

    async def test_silent_log_is_an_error_not_an_empty_report(self):
        with self.assertRaisesRegex(RuntimeError, 'не пришёл'):
            await self.collect([[]], seconds=0.1)

    async def test_local_write_failure_is_not_a_drop(self):
        def broken(e, msg): raise OSError(28, 'No space left on device')
        with self.assertRaises(OSError):
            await self.collect([['before']], on_entry=broken)

    async def test_stop_ends_collection_before_the_deadline(self):
        seen = []
        def on_entry(e, msg): seen.append(msg)
        loop = asyncio.get_running_loop(); started = loop.time()
        await self.collect([['a', 'b', 'c']], seconds=30, on_entry=on_entry, stop=lambda: 'b' in seen)
        self.assertEqual(seen, ['a', 'b'])
        self.assertLess(loop.time() - started, 5)


class CloudBackupTest(unittest.TestCase):
    @staticmethod
    def device(values):
        return SimpleNamespace(get_value=AsyncMock(return_value=values))

    def test_reads_last_backup_from_lockdown(self):
        # Values read from an iPhone 16 Pro Max / iOS 27.0.1: the backup ended 2026-10-04 11:41:53 UTC.
        backup = asyncio.run(carrier.cloud_backup(self.device(
            {'CloudBackupEnabled': True, 'LastCloudBackupDate': 812806913, 'LastCloudBackupTZ': 'GMT+3'})))
        self.assertEqual(carrier.datetime.fromisoformat(backup['last']).timestamp(), 1791114060)
        now = carrier.datetime.fromisoformat('2026-10-04T22:42+03:00')
        self.assertIn('последняя 8 ч назад', carrier.backup_warning(backup, now))
        self.assertIn('Держите iPhone разблокированным', carrier.backup_warning({'enabled': True, 'last': None}))

    def test_disabled_or_missing_backup_prints_nothing(self):
        from pymobiledevice3.exceptions import MissingValueError
        self.assertIsNone(asyncio.run(carrier.cloud_backup(self.device({'CloudBackupEnabled': False}))))
        self.assertIsNone(asyncio.run(carrier.cloud_backup(self.device({}))))
        missing = SimpleNamespace(get_value=AsyncMock(side_effect=MissingValueError('MissingValue', 'x', '27.0.1')))
        self.assertIsNone(asyncio.run(carrier.cloud_backup(missing)))
        from pymobiledevice3.exceptions import ConnectionTerminatedError, GetProhibitedError
        prohibited = SimpleNamespace(get_value=AsyncMock(side_effect=GetProhibitedError('GetProhibited', 'x', '27.0.1')))
        self.assertIsNone(asyncio.run(carrier.cloud_backup(prohibited)))
        # A dropped link is not a missing value: it stays an error the retry loop sees.
        dropped = SimpleNamespace(get_value=AsyncMock(side_effect=ConnectionTerminatedError()))
        with self.assertRaises(ConnectionTerminatedError):
            asyncio.run(carrier.cloud_backup(dropped))
        self.assertIsNone(carrier.backup_warning(None))

    def test_plist_date_is_utc(self):
        # The same moment as a plist date: plistlib returns it naive, in UTC.
        backup = asyncio.run(carrier.cloud_backup(self.device(
            {'CloudBackupEnabled': True, 'LastCloudBackupDate': carrier.datetime(2026, 10, 4, 11, 41, 53)})))
        self.assertEqual(carrier.datetime.fromisoformat(backup['last']).timestamp(), 1791114060)


class DiagnoseTest(unittest.TestCase):
    # Lines from a real CommCenter log (iPhone 16 Pro Max, iOS 27.0.1, MegaFon, airplane mode on and off).
    IKE_LINES = [
        'Cancelling client BA2D064AF2C415DF for <NEIKEv2Transport> UDP NAT-T 10.10.10.150:4500 -> 85.26.231.145:4500',
        'IKEv2IKESA[13.13, BA2D064AF2C415DF-A96D618205B09415] state Connected -> Disconnected error (null) -> '
        'Error Domain=NEIKEv2ErrorDomain Code=2 "FailedToSend: delete reply" UserInfo={NSLocalizedDescription=x}',
    ]

    @staticmethod
    def entry(text, category=''):
        return SimpleNamespace(message=text, label=SimpleNamespace(subsystem='com.apple.CommCenter', category=category))

    def test_epdg_block_reports_gateway_state_and_error(self):
        state = {}; collect = carrier.diag_collect(state)
        for line in self.IKE_LINES:
            collect(self.entry(line), line)
        report = carrier.diag_report(state, [{'Slot': 'kOne', 'MCC': '250', 'MNC': '02'}])
        self.assertIn('ePDG                 85.26.231.145', report)
        self.assertIn('Connected → Disconnected', report)
        self.assertIn('код 2: FailedToSend: delete reply', report)

    def test_settles_only_after_every_sim_registered_again_after_the_drop(self):
        rows = [{'Slot': 'kOne'}, {'Slot': 'kTwo'}]
        reg = 'ImsRegistrationState: UE is Registered for Voice+Sms on kLTE (CarrierBundle)'
        clock = [100.0]
        with patch.object(carrier.time, 'monotonic', lambda: clock[0]):
            on_entry, done = carrier.registered_again({}, rows, carrier.diag_collect({}))
            # Registration before the airplane cycle proves nothing.
            on_entry(self.entry(reg, '5wi.ctr.1.1'), reg); on_entry(self.entry(reg, '5wi.ctr.2.1'), reg)
            clock[0] += 60; self.assertFalse(done())
            on_entry.reset()
            on_entry(self.entry(reg, '5wi.ctr.1.1'), reg)
            clock[0] += 60; self.assertFalse(done())
            on_entry(self.entry(reg, '5wi.ctr.2.1'), reg)
            clock[0] += carrier.DIAG_SETTLE_SECONDS - 1; self.assertFalse(done())
            clock[0] += 1; self.assertTrue(done())

    def test_settles_after_airplane_mode_turned_off_without_a_drop(self):
        reg = 'ImsRegistrationState: UE is Registered for Voice+Sms on iWLAN (CarrierBundle)'
        clock = [100.0]
        with patch.object(carrier.time, 'monotonic', lambda: clock[0]):
            on_entry, done = carrier.registered_again({}, [{'Slot': 'kOne'}], carrier.diag_collect({}))
            for line in ('Airplane mode changed from false to true', reg):
                on_entry(self.entry(line, 'cm' if 'Airplane' in line else '5wi.ctr.1.1'), line)
            clock[0] += 60; self.assertFalse(done())  # still in airplane mode
            for line in ('Airplane mode changed from true to false', reg):
                on_entry(self.entry(line, 'cm' if 'Airplane' in line else '5wi.ctr.1.1'), line)
            clock[0] += carrier.DIAG_SETTLE_SECONDS; self.assertTrue(done())

    def test_no_sims_never_settles(self):
        on_entry, done = carrier.registered_again({}, [], carrier.diag_collect({}))
        on_entry.reset()
        self.assertFalse(done())

    def test_enter_is_not_read_without_a_terminal(self):
        with patch.object(carrier.sys, 'stdin', io.StringIO('\n')):
            self.assertIsNone(carrier.enter_pressed())


class ErrorTextTest(unittest.IsolatedAsyncioTestCase):
    def test_windows_backend_dll_failure_explains_how_to_reinstall_itunes(self):
        error = "Failed to load dynlib/dll 'C:\\Apple\\AirTrafficHost.dll'. Most likely this dynlib/dll was not found when the application was frozen."
        message = carrier.backend_error(error, 'win32')
        self.assertIn(error, message)
        self.assertIn('Причина: не удалось найти или загрузить библиотеки Apple', message)
        self.assertIn('Удалите iTunes и установите его по ссылке ниже:', message)
        self.assertIn('https://4pda.to/forum/index.php?showtopic=554020&st=3760#entry107393362', message)
        self.assertNotIn('Удалите iTunes', carrier.backend_error(error, 'darwin'))
        self.assertNotIn('Удалите iTunes', carrier.backend_error('host timed out', 'win32'))

    def test_empty_exceptions_get_readable_text(self):
        from pymobiledevice3.exceptions import ConnectionTerminatedError, ConnectionFailedError
        self.assertEqual(carrier.error_text(TimeoutError()), 'время ожидания истекло')
        self.assertEqual(carrier.error_text(ConnectionTerminatedError()), 'связь с iPhone оборвалась')
        self.assertEqual(carrier.error_text(ConnectionFailedError()), 'связь с iPhone оборвалась')
        self.assertEqual(carrier.error_text(RuntimeError('текст')), 'текст')
        self.assertEqual(carrier.error_text(KeyError()), 'KeyError')
        self.assertEqual(carrier.error_line(KeyError()), 'KeyError')
        self.assertEqual(carrier.error_line(asyncio.CancelledError()), 'CancelledError')
        self.assertEqual(carrier.error_line(TimeoutError()), 'TimeoutError: время ожидания истекло')
        with patch.dict(sys.modules, {'pymobiledevice3': None}):  # broken install: still readable
            self.assertEqual(carrier.error_text(TimeoutError()), 'время ожидания истекло')
            self.assertEqual(carrier.error_text(ConnectionResetError()), 'связь с iPhone оборвалась')
            self.assertEqual(carrier.error_text(KeyError()), 'KeyError')

    async def silent_host(self, connection):
        async def never(): await asyncio.Event().wait()
        proc = SimpleNamespace(stdout=SimpleNamespace(readline=never), stderr=SimpleNamespace(read=AsyncMock(return_value=b'')),
                               stdin=SimpleNamespace(), returncode=None, kill=lambda: None, wait=AsyncMock(return_value=-9))
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(carrier.asyncio, 'create_subprocess_exec', AsyncMock(return_value=proc)), \
                patch.object(carrier, 'AIRTRAFFIC_SECONDS', 0.05), patch.object(carrier, 'CONNECTION', connection), \
                self.assertRaises(RuntimeError) as caught:
            await carrier.host_session('phone', [], AsyncMock(), pathlib.Path(directory))
        return caught.exception

    async def test_silent_host_over_wifi_fails_fast_with_a_cable_hint(self):
        error = await self.silent_host('Network')
        self.assertIn('AirTraffic не ответил по Wi-Fi', str(error))
        self.assertIn('Подключите кабель', str(error))
        self.assertFalse(carrier.transient_error(error))

    async def test_silent_host_over_usb_stays_transient(self):
        error = await self.silent_host('USB')
        self.assertIn('Сбой AirTraffic: AirTraffic не ответил', str(error))
        self.assertTrue(carrier.transient_error(error))

    async def test_timeout_inside_the_pause_keeps_its_own_cause(self):
        lines = iter([b'CARRIER_SWAP_JSON:{"event": "before-final-asset"}\n'])
        async def readline(): return next(lines)
        proc = SimpleNamespace(stdout=SimpleNamespace(readline=readline), stderr=SimpleNamespace(read=AsyncMock(return_value=b'')),
                               stdin=SimpleNamespace(), returncode=None, kill=lambda: None, wait=AsyncMock(return_value=-9))
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(carrier.asyncio, 'create_subprocess_exec', AsyncMock(return_value=proc)), \
                self.assertRaises(TimeoutError):
            await carrier.host_session('phone', [], AsyncMock(side_effect=TimeoutError(60, 'Operation timed out')),
                                       pathlib.Path(directory))


class CatalogTest(unittest.TestCase):
    CATALOG = {'meta': {'ios': '27.0', 'deviceName': 'iPhone 17'},
               'bundles': [{'b': 'Vodafone_tr', 'country': 'Turkey', 'reg': '13191', 'ih': 'cellular', 'wroam': True,
                            'wn': 'vodafone TR Wi-Fi', 'lte': '4G', 'vs': False, 'evs': True, 'xcap': True, 'vvm': 'none'},
                           {'b': 'Vodafone_ro', 'reg': '+447786205094', 'ih': 'ims', 'wroam': False},
                           {'b': 'Exit_zero', 'reg': '00447786205094'}]}

    def load(self):
        with tempfile.TemporaryDirectory() as runs:
            pathlib.Path(runs, 'bundles.json').write_text(json.dumps(self.CATALOG), encoding='utf-8')
            with patch('urllib.request.urlopen', side_effect=AssertionError('fresh cache must not be refetched')):
                return carrier.load_catalog(runs)

    def test_passport_from_cache_warns_about_short_imessage_number(self):
        catalog = self.load()
        text = '\n'.join(carrier.passport_lines('Vodafone_tr.bundle', catalog))
        self.assertIn('местный номер 13191', text)
        self.assertIn('в роуминге — да', text)
        self.assertIn('приоритет дома — сотовая', text)
        self.assertIn('международный номер', '\n'.join(carrier.passport_lines('Vodafone_ro', catalog)))
        self.assertIn('Похожие: Vodafone_tr', carrier.passport_lines('Vodafon_tr', catalog)[0])
        self.assertIn('международный номер', '\n'.join(carrier.passport_lines('Exit_zero', catalog)))

    def test_case_only_mismatch_is_an_error_and_missing_catalog_is_silent(self):
        catalog = self.load()
        self.assertIn('Vodafone_tr', carrier.catalog_name_error('vodafone_TR.bundle', catalog))
        self.assertIsNone(carrier.catalog_name_error('Vodafone_tr.bundle', catalog))
        self.assertFalse(carrier.catalog_name_error('Unknown_xx', catalog))
        self.assertIsNone(carrier.catalog_name_error('vodafone_tr', None))
        self.assertEqual(carrier.passport_lines('Vodafone_tr', None), [])
        with tempfile.TemporaryDirectory() as runs, \
                patch('urllib.request.urlopen', side_effect=OSError('offline')):
            self.assertIsNone(carrier.load_catalog(runs))

    def test_downloaded_table_is_cached_atomically(self):
        response = unittest.mock.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(self.CATALOG).encode()
        with tempfile.TemporaryDirectory() as runs, patch('urllib.request.urlopen', return_value=response):
            self.assertIsNotNone(carrier.load_catalog(runs))
            self.assertEqual([p.name for p in pathlib.Path(runs).iterdir()], ['bundles.json'])

    INVALID_CATALOGS = (
        None, [], {'meta': None, 'bundles': [{'b': 'Vodafone_tr'}]},
        {'meta': [], 'bundles': []}, {'bundles': None}, {'bundles': {}},
        {'bundles': [None]}, {'bundles': [{'b': 123}]}, {'bundles': [{'b': True}]},
        {'bundles': [{'b': None}]}, {'bundles': [{'b': ''}]}, {'bundles': [{}]},
        {'bundles': [{'b': 'Vodafone_tr', 'ih': []}]},
        {'bundles': [{'b': 'Vodafone_tr', 'ih': {}}]},
    )

    def test_wrong_json_types_skip_passport_without_creating_cache(self):
        for catalog in self.INVALID_CATALOGS:
            with self.subTest(catalog=catalog), tempfile.TemporaryDirectory() as runs:
                response = unittest.mock.MagicMock()
                response.__enter__.return_value.read.return_value = json.dumps(catalog).encode()
                with patch('urllib.request.urlopen', return_value=response):
                    loaded = carrier.load_catalog(runs)
                self.assertIsNone(loaded)
                self.assertIsNone(carrier.catalog_name_error('Vodafone_tr.bundle', loaded))
                self.assertEqual(carrier.passport_lines('Vodafone_tr.bundle', loaded), [])
                self.assertEqual(list(pathlib.Path(runs).iterdir()), [])

    def test_invalid_download_preserves_and_uses_stale_cache(self):
        import os
        for catalog in self.INVALID_CATALOGS:
            with self.subTest(catalog=catalog), tempfile.TemporaryDirectory() as runs:
                cache = pathlib.Path(runs, 'bundles.json')
                original = json.dumps(self.CATALOG).encode()
                cache.write_bytes(original)
                os.utime(cache, (0, 0))
                response = unittest.mock.MagicMock()
                response.__enter__.return_value.read.return_value = json.dumps(catalog).encode()
                with patch('urllib.request.urlopen', return_value=response) as download:
                    loaded = carrier.load_catalog(runs)
                download.assert_called_once()
                self.assertEqual(cache.read_bytes(), original)
                self.assertEqual([p.name for p in pathlib.Path(runs).iterdir()], ['bundles.json'])
                self.assertIn('местный номер 13191', '\n'.join(carrier.passport_lines('Vodafone_tr', loaded)))

    def test_wrong_types_in_existing_cache_are_ignored(self):
        for catalog in self.INVALID_CATALOGS:
            with self.subTest(catalog=catalog), tempfile.TemporaryDirectory() as runs:
                pathlib.Path(runs, 'bundles.json').write_text(json.dumps(catalog), encoding='utf-8')
                with patch('urllib.request.urlopen', side_effect=AssertionError('fresh cache')) as download:
                    loaded = carrier.load_catalog(runs)
                download.assert_not_called()
                self.assertIsNone(loaded)
                self.assertEqual(carrier.passport_lines('Vodafone_tr', loaded), [])


class OutcomeTest(unittest.TestCase):
    def test_rescan_outcome_names_what_ios_chose(self):
        r = lambda selected, verified=True: {'expected': 'Vodafone_tr.bundle', 'selected': selected, 'verified': verified}
        self.assertEqual(carrier.slot_outcome(r('Vodafone_tr.bundle'), True), 'Vodafone_tr — подпись принята')
        self.assertEqual(carrier.slot_outcome(r('MTS_ru.bundle'), False), 'iOS выбрала MTS_ru вместо Vodafone_tr')
        self.assertIn('нет выбора пакета', carrier.slot_outcome(r(None, False), False))
        self.assertIn('подпись не принята', carrier.slot_outcome(r('Vodafone_tr.bundle', False), False))


class GrappaTest(unittest.TestCase):
    LINE = ('Sep 30 23:58:12 iPhone atc(AirTrafficDevice)[56] <Error>: '
            'Grappa session could not be established. Aborting\n')

    def test_refusal_is_found_in_the_device_log_only_when_logged(self):
        with tempfile.TemporaryDirectory() as temp:
            log = pathlib.Path(temp) / 'device.log'
            self.assertFalse(carrier.grappa_refused(log))
            log.write_text('atc(AirTrafficDevice)[56] <Notice>: SyncAllowed\n', encoding='utf-8')
            self.assertFalse(carrier.grappa_refused(log))
            log.write_text(self.LINE, encoding='utf-8')
            self.assertTrue(carrier.grappa_refused(log))

    def test_hint_is_not_retried_and_names_the_fix_on_windows(self):
        for platform, fix in (('win32', 'https://4pda.to/forum/index.php?showtopic=554020&st=3760#entry107393362'), ('darwin', 'блок отладки выше')):
            with self.subTest(platform=platform), patch.object(carrier.sys, 'platform', platform):
                hint = carrier.grappa_hint()
                self.assertIn(fix, hint)
                self.assertIn(carrier.GRAPPA_REFUSED, hint)
                self.assertFalse(carrier.transient_error(RuntimeError(hint)))

    def test_only_the_host_failure_becomes_a_refusal(self):
        cause = 'Сбой AirTraffic: Синхронизация закончилась преждевременно'
        with tempfile.TemporaryDirectory() as temp:
            log = pathlib.Path(temp) / 'device.log'
            log.write_text(self.LINE, encoding='utf-8')
            refused = carrier.grappa_failure(RuntimeError(cause), log)
            self.assertIsInstance(refused, carrier.GrappaRefused)
            self.assertIn(cause, str(refused))
            self.assertFalse(carrier.transient_error(refused))
            # A dropped AFC link during the pause stays itself and is retried.
            self.assertIsNone(carrier.grappa_failure(ConnectionResetError(54, 'reset'), log))
            self.assertIsNone(carrier.grappa_failure(RuntimeError('Книги изменились'), log))
            log.write_text('atc <Notice>: SyncFailed\n', encoding='utf-8')
            self.assertIsNone(carrier.grappa_failure(RuntimeError(cause), log))


class LocalNetworkTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        patcher = patch.object(carrier, 'LOCAL_NETWORK_WAIT', 0)
        patcher.start(); self.addCleanup(patcher.stop)

    def test_sockaddr_ipv6_and_ipv4(self):
        import socket
        ipv6 = bytes([28, socket.AF_INET6, 0xf2, 0x7e]) + bytes(4) + \
            bytes.fromhex('fe800000000000001c2d7734a92c3e3a') + (12).to_bytes(4, sys.byteorder)
        self.assertEqual(carrier.sockaddr(ipv6), (socket.AF_INET6, ('fe80::1c2d:7734:a92c:3e3a', 62078, 0, 12)))
        ipv4 = bytes([16, socket.AF_INET, 0, 0, 192, 168, 1, 5]) + bytes(8)
        self.assertEqual(carrier.sockaddr(ipv4), (socket.AF_INET, ('192.168.1.5', 62078)))

    def denied(self, error):
        import socket
        sock = unittest.mock.MagicMock()
        sock.__enter__.return_value.connect.side_effect = error
        with patch.object(carrier.sys, 'platform', 'darwin'), \
             patch.object(carrier, 'usbmux_network_address', return_value=(socket.AF_INET6, ('fe80::1', 62078, 0, 12))), \
             patch('socket.socket', return_value=sock):
            return carrier.local_network_denied('phone')

    def test_only_ehostunreach_counts_as_denied(self):
        self.assertTrue(self.denied(OSError(65, 'No route to host')))
        self.assertFalse(self.denied(OSError(61, 'Connection refused')))
        self.assertFalse(self.denied(TimeoutError()))
        self.assertFalse(self.denied(None))

    def test_slow_ehostunreach_is_a_missing_phone_not_a_refusal(self):
        with patch.object(carrier.time, 'monotonic', side_effect=[0.0, 2.0]):
            self.assertFalse(self.denied(OSError(65, 'No route to host')))

    def usbmux(self, *devices):
        import plistlib, socket, struct
        body = plistlib.dumps({'DeviceList': [{'DeviceID': i, 'Properties': p} for i, p in enumerate(devices)]})
        data = bytearray(struct.pack('<IIII', 16 + len(body), 1, 8, 1) + body)
        sock = unittest.mock.MagicMock()
        def recv(n):
            chunk = bytes(data[:n]); del data[:n]; return chunk
        sock.__enter__.return_value.recv.side_effect = recv
        with patch('socket.socket', return_value=sock):
            return carrier.usbmux_network_address('phone')

    @unittest.skipUnless(hasattr(__import__('socket'), 'AF_UNIX'), 'usbmuxd socket is macOS-only')
    def test_usbmux_address_and_cable_skip(self):
        import socket
        raw = bytes([16, socket.AF_INET, 0, 0, 192, 168, 1, 5]) + bytes(8)
        wifi = {'SerialNumber': 'phone', 'ConnectionType': 'Network', 'NetworkAddress': raw}
        self.assertEqual(self.usbmux(wifi), (socket.AF_INET, ('192.168.1.5', 62078)))
        self.assertIsNone(self.usbmux(wifi, {'SerialNumber': 'phone', 'ConnectionType': 'USB'}))
        self.assertIsNone(self.usbmux({**wifi, 'SerialNumber': 'other'}))

    def test_unknown_address_or_other_platform_is_not_denied(self):
        with patch.object(carrier.sys, 'platform', 'darwin'), \
             patch.object(carrier, 'usbmux_network_address', return_value=None):
            self.assertFalse(carrier.local_network_denied('phone'))
        with patch.object(carrier.sys, 'platform', 'win32'), \
             patch.object(carrier, 'usbmux_network_address') as address:
            self.assertFalse(carrier.local_network_denied('phone'))
            address.assert_not_called()

    async def test_denied_wifi_stops_before_any_stage(self):
        args = SimpleNamespace(udid=None, wait_seconds=1, diagnose=False, watch_call=False, report=False,
                               attempts=2, runs=pathlib.Path('.'), status=False, recover=False)
        with patch.object(carrier, 'CONNECTION', 'Network'), \
             patch.object(carrier, 'choose_device', AsyncMock(return_value='phone')), \
             patch.object(carrier, 'pending', return_value=[]), \
             patch.object(carrier, 'local_network_denied', return_value=True), \
             patch.object(carrier, 'execute', AsyncMock()) as execute, \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, 'Локальная сеть'):
                await carrier.execute_with_retry(args, {})
            execute.assert_not_awaited()
        args.status = True
        with patch.object(carrier, 'CONNECTION', 'Network'), \
             patch.object(carrier, 'choose_device', AsyncMock(return_value='phone')), \
             patch.object(carrier, 'local_network_denied', return_value=True) as check, \
             patch.object(carrier, 'execute', AsyncMock(return_value=0)):
            self.assertEqual(await carrier.execute_with_retry(args, {}), 0)
            check.assert_not_called()

    async def test_allowing_in_the_alert_lets_the_install_go_on(self):
        # The first probe is refused while macOS shows its alert; the next one, after "Allow", passes.
        with patch.object(carrier, 'CONNECTION', 'Network'), patch.object(carrier, 'LOCAL_NETWORK_WAIT', 3), \
             patch.object(carrier, 'local_network_denied', side_effect=[True, True, False]) as check, \
             patch.object(carrier.asyncio, 'sleep', AsyncMock()), contextlib.redirect_stdout(io.StringIO()) as out:
            await carrier.require_local_network('phone')
        self.assertEqual(check.call_count, 3)
        self.assertIn('Разрешить', out.getvalue())

    async def test_unfinished_stage_is_reported_before_the_permission(self):
        args = SimpleNamespace(udid=None, wait_seconds=1, diagnose=False, watch_call=False, report=False,
                               attempts=1, runs=pathlib.Path('.'), status=False, recover=False)
        with patch.object(carrier, 'CONNECTION', 'Network'), \
             patch.object(carrier, 'choose_device', AsyncMock(return_value='phone')), \
             patch.object(carrier, 'pending', return_value=['stage']), \
             patch.object(carrier, 'local_network_denied', return_value=True) as check, \
             patch.object(carrier, 'execute', AsyncMock(side_effect=RuntimeError('Прошлая операция не завершилась'))), \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, 'Прошлая операция'):
                await carrier.execute_with_retry(args, {})
            check.assert_not_called()

    async def test_recover_over_wifi_skips_the_early_check(self):
        args = SimpleNamespace(udid=None, wait_seconds=1, diagnose=False, watch_call=False, report=False,
                               attempts=1, runs=pathlib.Path('.'), status=False, recover=pathlib.Path('AUTO'))
        with patch.object(carrier, 'CONNECTION', 'Network'), \
             patch.object(carrier, 'choose_device', AsyncMock(return_value='phone')), \
             patch.object(carrier, 'pending', return_value=['stage']), \
             patch.object(carrier, 'local_network_denied', return_value=True) as check, \
             patch.object(carrier, 'execute', AsyncMock(return_value=0)), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(await carrier.execute_with_retry(args, {}), 0)
            check.assert_not_called()

    async def test_denied_rollback_is_not_retried_by_auto_recovery(self):
        args = SimpleNamespace(udid=None, wait_seconds=1, diagnose=False, watch_call=False, report=False,
                               attempts=2, runs=pathlib.Path('.'), status=False, recover=pathlib.Path('AUTO'))
        with patch.object(carrier, 'CONNECTION', 'Network'), \
             patch.object(carrier, 'choose_device', AsyncMock(return_value='phone')), \
             patch.object(carrier, 'pending', return_value=['stage']), \
             patch.object(carrier, 'execute', AsyncMock(side_effect=carrier.LocalNetworkDenied('x'))) as execute, \
             patch.object(carrier, 'recover_all', AsyncMock()) as recover_all, \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(carrier.LocalNetworkDenied):
                await carrier.execute_with_retry(args, {})
            recover_all.assert_not_awaited()
            self.assertEqual(execute.await_count, 1)

    def stage(self, root, **journal):
        folder = root / 'stage'; folder.mkdir()
        carrier.write_tree_zip(folder / 'books.zip', {})
        carrier.save_json(folder / 'books.json', {'hash': carrier.tree_hash({}), 'existed': True})
        catalog = {'catalog': ('d', b'')}
        carrier.write_tree_zip(folder / 'original.zip', catalog)
        carrier.save_json(folder / 'journal.json', {'target': carrier.TARGET, 'udid_hash': carrier.digest(b'phone'),
            'exported': 'airlift-saved-' + 'a' * 20, 'original_hash': carrier.tree_hash(catalog), **journal})
        return folder

    def offline_recovery(self, stack):
        # A denied Local Network, an empty phone and mocked AFC: what recover_stage reaches is what it needs.
        afc = AsyncMock(); afc.__aenter__.return_value = afc
        stack.enter_context(patch.object(carrier, 'CONNECTION', 'Network'))
        stack.enter_context(patch('pymobiledevice3.services.afc.AfcService', return_value=afc))
        stack.enter_context(patch.object(carrier, 'exists', AsyncMock(return_value=False)))
        stack.enter_context(patch.object(carrier, 'local_network_denied', return_value=True))
        return (stack.enter_context(patch.object(carrier, 'restore_books', AsyncMock(return_value=[]))),
                stack.enter_context(patch.object(carrier, 'transfer', AsyncMock())))

    async def test_books_only_rollback_needs_no_local_network(self):
        # Carrier stage finished with Books left; and an early stage whose catalog never left.
        for journal in ({'complete': True, 'phase': 'placement-observed'}, {'complete': False, 'phase': 'staging'}):
            with self.subTest(journal=journal), tempfile.TemporaryDirectory() as temp, contextlib.ExitStack() as stack:
                root = pathlib.Path(temp)
                folder = self.stage(root, **journal); (folder / 'original.zip').unlink()
                books, transfer = self.offline_recovery(stack)
                await carrier.recover_stage(SimpleNamespace(udid='phone'), folder, root)
                books.assert_awaited_once()
                transfer.assert_not_awaited()
                self.assertEqual(carrier.read_json(folder / 'journal.json')['recovered_by'], str(root))

    async def test_catalog_rollback_stops_on_denied_local_network(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.ExitStack() as stack:
            root = pathlib.Path(temp)
            folder = self.stage(root, complete=False, phase='placement', requires_recovery=True)
            books, transfer = self.offline_recovery(stack)
            with self.assertRaises(carrier.LocalNetworkDenied):
                await carrier.recover_stage(SimpleNamespace(udid='phone'), folder, root)
            books.assert_awaited_once()
            transfer.assert_not_awaited()
            self.assertNotIn('recovered_by', carrier.read_json(folder / 'journal.json'))


class VersionTest(unittest.TestCase):
    def test_cli_version_and_help_work_without_apple_services(self):
        for flag, expected in (('--version', f'CarrierSIM {VERSION}'), ('--help', '--recover')):
            result = subprocess.run([sys.executable, str(carrier.ROOT / 'carrier.py'), flag],
                                    capture_output=True, text=True, encoding='utf-8')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(expected, result.stdout)

    def test_menu_displays_version(self):
        with patch('builtins.input', return_value='0'), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertIsNone(launch.menu())
        self.assertIn(f'CarrierSIM · {VERSION}', output.getvalue())

    def test_other_profile_shows_plan_and_writes_only_after_yes(self):
        for answer, runs in (('', 2), ('д', 2), ('н', 1)):
            # menu: 7, bundle name, SIM 2, then the confirmation, "press Enter", and 0 to quit.
            inputs = iter(['7', 'Vodafone_tr', '2', answer, '', '0'])
            with self.subTest(answer=answer), patch('builtins.input', lambda *_: next(inputs)), \
                    patch.object(launch, 'check_writable'), patch.object(launch, 'python_environment'), \
                    patch.object(launch, 'run_carrier', return_value=0) as run, patch.object(sys, 'argv', ['launch.py']), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(launch.main(), 0)
            calls = [c.args[1] for c in run.call_args_list]
            self.assertEqual(len(calls), runs)
            self.assertEqual(calls[0], ['--bundle', 'Vodafone_tr', '--sims', '2', '--status'])
            if runs == 2: self.assertEqual(calls[1], ['--bundle', 'Vodafone_tr', '--sims', '2'])

    def test_other_profile_does_not_ask_when_the_plan_writes_nothing(self):
        # menu: 7, bundle name, SIM 2, "press Enter", and 0 to quit — no confirmation question.
        inputs = iter(['7', 'Vodafone_tr', '2', '', '0'])
        with patch('builtins.input', lambda *_: next(inputs)), \
                patch.object(launch, 'check_writable'), patch.object(launch, 'python_environment'), \
                patch.object(launch, 'run_carrier', return_value=launch.NOTHING_TO_WRITE) as run, \
                patch.object(sys, 'argv', ['launch.py']), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(launch.main(), 0)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.kwargs['env']['CARRIERSIM_PLAN'], '1')
        self.assertIn('Записывать нечего', output.getvalue())
        self.assertNotIn('Действие не завершено', output.getvalue())
        self.assertEqual(launch.NOTHING_TO_WRITE, carrier.NOTHING_TO_WRITE)

    def test_log_environment_and_error_report_identify_version(self):
        with tempfile.TemporaryDirectory() as directory:
            run = pathlib.Path(directory)
            with patch.dict(carrier.DIAG, {}, clear=True):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    stdout, stderr = sys.stdout, sys.stderr
                    carrier.start_session_log(run)
                    log = sys.stdout.log
                    try:
                        print('console output')
                        print('error output', file=sys.stderr)
                    finally:
                        sys.stdout, sys.stderr = stdout, stderr
                        log.close()
                text = next(run.glob('*session.log')).read_text(encoding='utf-8')
                self.assertTrue(text.startswith(f'CarrierSIM {VERSION} · сборка '))
                self.assertIn('console output', text)
                self.assertIn('error output', text)
                carrier.save_environment(run)
                environment = carrier.read_json(run / 'environment.json')
                self.assertEqual(environment['CarrierSIM'], VERSION)
                self.assertEqual(len(environment['Сборка скрипта']), 12)
                carrier.DIAG['run'] = run
                with contextlib.redirect_stderr(io.StringIO()):
                    carrier.print_diagnostics(RuntimeError('test failure'))
                self.assertIn(f'CarrierSIM: {VERSION}', (run / 'diagnostics.txt').read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
