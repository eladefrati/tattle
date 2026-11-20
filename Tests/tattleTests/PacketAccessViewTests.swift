import XCTest
@testable import tattle

/// The words the Network tab and Packet access use for each state of the broker, as agreed
/// before they were built.
final class PacketAccessViewTests: XCTestCase {
    typealias View = PacketAccessView

    func testLinkTitle() {
        XCTAssertEqual(View.linkTitle(.absent, capturing: false), "Allow packet access")
        XCTAssertEqual(View.linkTitle(.current, capturing: false), "Packet access off")
        XCTAssertEqual(View.linkTitle(.current, capturing: true), "Packet access on")
        // A broker from another build can still serve this one.
        XCTAssertEqual(View.linkTitle(.stale(.otherBuild), capturing: true), "Packet access on")
        for staleness: CaptureBroker.Staleness in [.incomplete, .notLoaded, .otherUser(502), .otherBuild] {
            XCTAssertEqual(View.linkTitle(.stale(staleness), capturing: false), "Packet access: install again")
        }
    }

    func testHeaderSaysWhyNamesAreOff() {
        XCTAssertEqual(View.namesOff(.stale(.otherBuild)), "Destinations are addresses: the packet-access broker on this Mac does not serve this copy of Tattle")
        XCTAssertEqual(View.namesOff(.absent), "Destinations are addresses: names need packet access, which Tattle does not have yet")
    }

    /// The text shown before install names every packet Tattle reads: the first packets of each
    /// connection, and this Mac's DNS lookups and their replies.
    func testInstallExplanationNamesEveryPacketTattleReads() {
        let text = CaptureBroker.installExplanation
        XCTAssertTrue(text.hasPrefix("Names for connections come from the first packets of each one and from this Mac's DNS lookups and their replies, which only a root process may read."), text)
        XCTAssertTrue(text.contains("Tattle reads only those packets."), text)
    }

    func testExplanationAndButtonForEachState() {
        XCTAssertNil(View.explanation(.absent, capturing: false))
        XCTAssertNil(View.explanation(.current, capturing: true))
        XCTAssertEqual(View.explanation(.stale(.otherBuild), capturing: false),
                       "The installed broker is from another build of Tattle. Install it again so it recognises this one.")
        XCTAssertEqual(View.explanation(.stale(.otherBuild), capturing: true),
                       "The installed broker is from another build of Tattle. It still serves this one; install it again to update it.")
        XCTAssertEqual(View.explanation(.stale(.otherUser(502)), capturing: false),
                       "The installed broker serves another account on this Mac (user ID 502), so it refuses this one. Installing it here replaces theirs.")
        XCTAssertEqual(View.explanation(.stale(.incomplete), capturing: false),
                       "The packet-access broker is only partly installed and cannot run. Install it again, or remove what is left.")
        XCTAssertEqual(View.explanation(.stale(.notLoaded), capturing: false),
                       "The packet-access broker is installed but not running. Install it again to start it.")

        XCTAssertEqual(View.installLabel(.absent), "Install")
        XCTAssertNil(View.installLabel(.current), "Remove only")
        XCTAssertEqual(View.installLabel(.stale(.otherUser(502))), "Install for this account")
        XCTAssertEqual(View.installLabel(.stale(.otherBuild)), "Install again")
    }
}
