import Foundation
import XCTest

/// Fails when `work` takes time by the square of its input's size, not in proportion to it.
/// The larger input is 16 times the smaller: in proportion that is 16 times the time, by the
/// square 256, and the bound stands between them at 64. So that a busy machine cannot fail
/// work that is in proportion, the time is the calling thread's own on a processor, which
/// other programs' work does not add to; the two sizes are run in turn, so what does slow
/// this thread (a slower core, a hot machine) falls on both; and the best of three is kept.
func assertTimeGrowsInProportion<Input>(
    from small: Int, input: (Int) throws -> Input, _ work: (Input) -> Void,
    file: StaticString = #filePath, line: UInt = #line
) rethrows {
    let inputs = (few: try input(small), many: try input(small * 16))
    func seconds(_ input: Input) -> Double {
        let start = clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID)
        work(input)
        return Double(clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID) - start) / 1e9
    }
    var best = (few: Double.infinity, many: Double.infinity)
    for _ in 0..<3 {
        best.few = min(best.few, seconds(inputs.few))
        best.many = min(best.many, seconds(inputs.many))
    }
    XCTAssertLessThan(best.many, best.few * 64, "\(best.few) s for \(small), \(best.many) s for \(small * 16): \(best.many / best.few) times",
                      file: file, line: line)
}
