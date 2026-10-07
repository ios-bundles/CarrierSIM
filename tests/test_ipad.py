"""iPad path, backup binding and no-SIM regressions; no device writes."""
import contextlib
import io
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

import carrier


class IpadTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.context = patch.multiple(carrier, DEVICE_FAMILY=carrier.DEVICE_FAMILY,
            TARGET=carrier.TARGET, SYSTEM_BUNDLE_DIR=carrier.SYSTEM_BUNDLE_DIR,
            SYSTEM_PREFIX=carrier.SYSTEM_PREFIX)
        self.context.start()
        self.addCleanup(self.context.stop)
        self.info = {'ProductType': 'iPad14,8', 'HardwareModel': 'J407AP',
                     'ProductVersion': '27.0.1', 'BuildVersion': '24A446',
                     'ActivationState': 'Activated', 'TelephonyCapability': False}

    def test_ipad_links_and_staging_use_ipad_directories(self):
        carrier.configure_device(self.info)
        row = {'Slot': 'kOne', 'MCC': '257', 'MNC': '02',
               'InternationalMobileSubscriberIdentity': '257021234567890'}
        sims = carrier.select_sims([row], {'default': 'MTS_ua.bundle'}, any_mcc=False)
        plan = carrier.make_plan({}, sims)
        self.assertEqual(carrier.TARGET, '/var/mobile/Library/Carrier Bundles/iPad')
        self.assertEqual(plan[row['InternationalMobileSubscriberIdentity']],
            ('l', b'../../../../../../System/Library/Carrier Bundles/iPad/MTS_ua.bundle'))
        import zipfile
        with zipfile.ZipFile(io.BytesIO(carrier.staging_archive(plan))) as archive:
            names = archive.namelist()
            self.assertIn('System/Library/Carrier Bundles/iPad/MTS_ua.bundle/', names)
            self.assertFalse(any('Carrier Bundles/iPhone' in n for n in names))
        carrier.configure_device({'ProductType': 'iPhone18,3'})
        self.assertTrue(carrier.bundle_link('MTS_ua.bundle')[1].endswith(b'Carrier Bundles/iPhone/MTS_ua.bundle'))

    def test_backup_binding_rejects_other_device_family(self):
        device = SimpleNamespace(udid='test-device')
        record = {'udid_hash': carrier.digest(b'test-device'),
                  'target': '/var/mobile/Library/Carrier Bundles/iPad'}
        carrier.configure_device(self.info)
        carrier.bound(record, device)
        carrier.configure_device({'ProductType': 'iPhone18,3'})
        with self.assertRaises(RuntimeError):
            carrier.bound(record, device)

    def test_ipad_trigger_is_independent_and_has_signed_cellular_overrides(self):
        import tempfile
        assets = carrier.load_assets()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'AVEA_tr_iPad.ipcc'
            path.write_bytes(assets['triggers/AVEA_tr_iPad.ipcc'][1])
            carrier.check_trigger(path, {'25001', '25702'}, {'Vodafone_ro.bundle', 'MTS_ua.bundle'})
            self.assertTrue(carrier.check_trigger_hardware(path, 'J311AP', warn=False))
            self.assertFalse(carrier.check_trigger_hardware(path, 'D84AP', warn=False))

    async def test_wifi_ipad_status_explains_no_modem_and_install_never_transfers(self):
        device = AsyncMock()
        device.get_value.side_effect = lambda key=None: [] if key else {'TelephonyCapability': False}
        args = SimpleNamespace(udid='test-device', wait_seconds=0, recover=None, status=True)
        with patch.object(carrier, 'ready_device', AsyncMock(return_value=device)), \
             patch.object(carrier, 'device_info', AsyncMock(return_value=self.info)), \
             patch.object(carrier, 'transfer', AsyncMock()) as transfer, \
             patch.object(carrier, 'install_trigger', AsyncMock()) as trigger, \
             patch.dict(carrier.DIAG, {}, clear=True), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(await carrier.execute(args, {}), 0)
            self.assertIn('iPad Wi-Fi без сотового модема', output.getvalue())
            args.status = False
            with self.assertRaisesRegex(RuntimeError, 'без сотового модема'):
                await carrier.execute(args, {})
            transfer.assert_not_awaited()
            trigger.assert_not_awaited()
        self.assertEqual(device.close.await_count, 2)

    async def test_wifi_ipad_missing_carrier_key_is_empty(self):
        from pymobiledevice3.exceptions import MissingValueError
        device = AsyncMock()
        async def get_value(key=None, domain=None):
            if domain:
                return {}
            if key == 'CarrierBundleInfoArray':
                raise MissingValueError('MissingValue', 'test-device', '27.0.1')
            return self.info.get(key)
        device.get_value.side_effect = get_value
        info = await carrier.device_info(device)
        self.assertEqual(info['carriers'], [])
        self.assertIsNone(info['cloud_backup'])
        self.assertFalse(info['TelephonyCapability'])
        self.assertEqual(await carrier.carrier_rows(device), [])
        device.get_value.side_effect = ConnectionError('USB disconnected')
        with self.assertRaises(ConnectionError):
            await carrier.carrier_rows(device)

    def test_cellular_without_active_sim_is_distinguished_from_wifi(self):
        carrier.configure_device(self.info)
        self.assertIn('активную SIM', carrier.no_cellular_sim({'TelephonyCapability': True}, []))
        self.assertIsNone(carrier.no_cellular_sim({'TelephonyCapability': True}, [{'Slot': 'kOne'}]))
        self.assertTrue(carrier.our_trace('Library/Carrier Bundles/iPad'))


if __name__ == '__main__':
    unittest.main()
