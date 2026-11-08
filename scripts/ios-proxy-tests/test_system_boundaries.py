"""Static regression checks for system-network launch boundaries (not iOS execution)."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2] / 'src/ios'

class SystemBoundaryAudit(unittest.TestCase):
    def body(self, path, signature):
        text = (ROOT / path).read_text()
        start = text.index(signature)
        return text[start:text.index('\n    }', start)]

    def test_oauth_login_rejects_before_creating_system_browser(self):
        for path in (ROOT / 'Providers').glob('*/OAuth/*OAuthManager.swift'):
            if 'SFSafariViewController(url:' in path.read_text():
                with self.subTest(path=path.name):
                    body = self.body(path.relative_to(ROOT), 'func login(instanceId: String) async throws {')
                    self.assertTrue(body.split('{', 1)[1].lstrip().startswith('try SystemProxyBoundary.requireAllowed('))
                    self.assertIn('try SystemProxyBoundary.requireAllowed(', self.body(path.relative_to(ROOT), 'private func presentSafariViewController'))

    def test_cloudkit_launches_and_destructive_operations_are_guarded(self):
        for path, signatures in {
            'Agent/Sync/CloudSyncEngine.swift': ['func start() async {', 'func deleteAllCloudData() async throws {', 'func discoverDeviceZones() async {'],
            'Agent/Sync/V2/ICloudSharedZoneTransport.swift': ['func start() async throws {', 'private func fetchRecentV2() async {', 'private func triggerV1Deletion() {'],
            'Agent/Sync/V2/MigrationEngine.swift': ['static func fetchAll() async throws', 'static func countOwnZone() async throws', 'static func purgeZone(zoneName:', 'static func deleteOwnZone(zoneName:', 'static func listAllZones() async throws'],
        }.items():
            for signature in signatures:
                with self.subTest(path=path, signature=signature):
                    body = self.body(path, signature)
                    self.assertRegex(body.split('{', 1)[1].lstrip(), r'^(try SystemProxyBoundary.requireAllowed|guard !AppProxyNetwork.strictEnabled)')

    def test_debug_cloudkit_cannot_bypass_strict_mode(self):
        for signature in ['private func handleSyncCKQuery(', 'private func handleSyncAllZones()', 'private func handleSyncZoneStats(']:
            self.assertIn('guard !AppProxyNetwork.strictEnabled', self.body('Debug/DebugJSONRPC.swift', signature)[:350])

    def test_media_and_extension_do_not_open_network_urls(self):
        native = self.body('NativeOffloads/PlayerOffloadBridge.swift', '@objc public static func openPlayer(')
        self.assertIn('guard url.isFileURL', native)
        for path in ['Views/Chat/Media/VideoPlayer.swift', 'Views/Chat/Media/AudioPreview.swift']:
            self.assertIn('guard fileURL.isFileURL', (ROOT / path).read_text())
        extension = (ROOT / 'ShareExtension/ShareViewModel.swift').read_text()
        self.assertIn('guard url.isFileURL else { return }', self.body('ShareExtension/ShareViewModel.swift', 'private func copyFileToShared('))
        self.assertIn('let url = item as? URL, url.isFileURL,', extension)

    def test_resume_respects_selected_sync_engine(self):
        self.assertIn('!SyncV2Bootstrap.shouldPauseV1()', self.body('Agent/Sync/CloudSyncEngine.swift', 'func proxyModeChanged()'))

    def test_local_files_remain_usable(self):
        body = self.body('Views/Settings/MountedFolderCoordinator.swift', 'static func ensureDownloaded(')
        self.assertIn('try SystemProxyBoundary.requireLocalFileAccess(url)', body)
        self.assertNotIn('try SystemProxyBoundary.requireAllowed', body.split('startDownloadingUbiquitousItem')[0].split('if values.ubiquitousItemDownloadingStatus')[0])

    def test_saved_sync_consent_is_not_changed_by_proxy_observers(self):
        for path in ['Agent/Sync/CloudSyncEngine.swift', 'Agent/Sync/V2/SyncCore.swift', 'Views/Settings/MountedFoldersManager.swift']:
            text = (ROOT / path).read_text()
            self.assertIn('.appProxyDidChange', text)
            self.assertIn('proxyModeChanged', text)
            body = self.body(path, 'func proxyModeChanged()')
            self.assertNotRegex(body, r'(isEnabled|userAllowWrite)\s*=')

    def test_provider_backup_and_mount_entry_are_blocked(self):
        for path, signature in [
            ('Agent/Backup/BackupDelivery.swift', 'static func copyToMountedFolder'),
            ('Views/Settings/MountedFoldersManager.swift', 'func add(pickedURL:'),
            ('Views/Settings/MountedFoldersManager.swift', 'func ensureActivated() async {'),
            ('Agent/Sync/ICloudBackupManager.swift', 'func backup(category:'),
            ('Agent/Sync/ICloudBackupManager.swift', 'func restore(from entry:'),
        ]:
            with self.subTest(path=path):
                self.assertRegex(self.body(path, signature).split('{', 1)[1].lstrip(), r'^(try SystemProxyBoundary.requireAllowed|guard !AppProxyNetwork.strictEnabled)')

if __name__ == '__main__':
    unittest.main()
