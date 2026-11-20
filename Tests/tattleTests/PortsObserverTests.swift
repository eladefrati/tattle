import XCTest
import os
@testable import tattle

final class PortsObserverTests: XCTestCase {
    /// /etc/services is read once, and off the main actor: parsing it held the panel at the
    /// first Ports refresh.
    @MainActor func testServiceNamesAreReadOnceOffTheMainActor() async {
        let reads = OSAllocatedUnfairLock<[Bool]>(initialState: [])
        let observer = PortsObserver(loadServices: {
            reads.withLock { $0.append(Thread.isMainThread) }
            return .empty
        })
        await observer.refresh()
        await observer.refresh()
        XCTAssertEqual(reads.withLock { $0 }, [false], "one read, not on the main thread")
    }
}
