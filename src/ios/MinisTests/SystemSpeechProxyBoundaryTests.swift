import XCTest
@testable import Minis

final class SystemSpeechProxyBoundaryTests: XCTestCase {
    func testStrictModeAllowsOnlySupportedOnDeviceRecognition() throws {
        XCTAssertTrue(try SystemVoiceProvider.requiresOnDeviceRecognition(
            requested: true, supported: true, strict: true))
        XCTAssertTrue(try SystemVoiceProvider.requiresOnDeviceRecognition(
            requested: nil, supported: true, strict: true))
        XCTAssertThrowsError(try SystemVoiceProvider.requiresOnDeviceRecognition(
            requested: false, supported: true, strict: true))
        let requests: [Bool?] = [nil, true, false]
        for requested in requests {
            XCTAssertThrowsError(try SystemVoiceProvider.requiresOnDeviceRecognition(
                requested: requested, supported: false, strict: true))
        }
    }

    func testDisabledProxyPreservesExistingRecognitionPreference() throws {
        XCTAssertFalse(try SystemVoiceProvider.requiresOnDeviceRecognition(
            requested: false, supported: true, strict: false))
        XCTAssertFalse(try SystemVoiceProvider.requiresOnDeviceRecognition(
            requested: true, supported: false, strict: false))
        XCTAssertTrue(try SystemVoiceProvider.requiresOnDeviceRecognition(
            requested: nil, supported: true, strict: false))
    }
}
