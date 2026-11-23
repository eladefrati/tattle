import SwiftUI

/// CPU, memory and network at a glance, across the top of the panel.
struct ResourcesLine: View {
    let sample: ResourceSample

    var body: some View {
        // The four readings lie on the glass itself, the numerals first, all one size so they
        // share a baseline. In and Out are as wide as their widest reading; CPU and Memory share
        // what is left, so their meters are one length and the memory total fits beside a
        // three-digit figure. Only the memory total's text may shrink.
        HStack(alignment: .top, spacing: 10) {
            stat("CPU", sample.cpu.formatted(.percent.precision(.fractionLength(0))), share: sample.cpu)
                .help(Self.allCoresHelp)
            stat("Memory", memory.used, memoryTotal, share: memoryShare)
            stat("In", rate(sample.bytesInPerSecond).value, rate(sample.bytesInPerSecond).unit, symbol: "arrow.down", widest: Self.widestRate)
            stat("Out", rate(sample.bytesOutPerSecond).value, rate(sample.bytesOutPerSecond).unit, symbol: "arrow.up", widest: Self.widestRate)
        }
        .padding(.horizontal, 10)
        .fixedSize(horizontal: false, vertical: true)
    }

    /// The two CPU figures use different scales, as Activity Monitor's do: the Mac's is all
    /// cores together, a row's is a share of one core.
    private static let cores = ProcessInfo.processInfo.activeProcessorCount
    static let allCoresHelp = "All \(cores) cores together. 100% is every core fully used."
    static let perCoreHelp = "Share of one core. 100% is one core fully used; this Mac has \(cores)."

    /// The widest rate a network reading shows.
    private static let widestRate = (value: "999.9", unit: "MB/s")

    /// One reading: what it is, its number, and a meter when it is a share of a whole. With
    /// `widest`, the column is as wide as that reading; without, it takes a share of the room left.
    private func stat(_ label: String, _ value: String, _ unit: String = "", share: Double? = nil, symbol: String? = nil,
                      widest: (value: String, unit: String)? = nil) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 3) {
                if let symbol {
                    Image(systemName: symbol).font(.system(size: 9, weight: .bold)).accessibilityHidden(true)
                }
                Text(label)
            }
            .font(.system(size: 11, weight: .medium))
            .foregroundStyle(.secondary)
            ZStack(alignment: .leading) {
                if let widest { reading(widest.value, widest.unit).hidden() }
                reading(value, unit)
            }
            if let share {
                GeometryReader { geometry in
                    Capsule().fill(.primary.opacity(0.12))
                    Capsule().fill(.tint).frame(width: max(4, geometry.size.width * min(max(share, 0), 1)))
                }
                .frame(height: 4)
                .padding(.top, 1)
                .accessibilityHidden(true)
            }
        }
        .frame(maxWidth: widest == nil ? .infinity : nil, alignment: .topLeading)
        .fixedSize(horizontal: widest != nil, vertical: false)
        // One static text, with the full unit: "Memory, 11.2 of 16 GB".
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(label), \(value)\(unit.isEmpty ? "" : " " + unit)")
    }

    /// A reading's number and its unit.
    private func reading(_ value: String, _ unit: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 3) {
            Text(value)
                .font(.system(size: 20, weight: .medium, design: .rounded))
                .monospacedDigit()
                .fixedSize()
            if !unit.isEmpty {
                Text(unit)
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .minimumScaleFactor(0.7)
            }
        }
        .lineLimit(1)
    }

    private var memoryShare: Double {
        sample.memory.total == 0 ? 0 : Double(sample.memory.used) / Double(sample.memory.total)
    }

    /// "11.2" and "of 16 GB": short enough for a quarter of the panel's width.
    private var memory: (used: String, total: String) {
        let gigabyte = 1_073_741_824.0
        let used = (Double(sample.memory.used) / gigabyte).formatted(.number.precision(.fractionLength(1)))
        let total = (Double(sample.memory.total) / gigabyte).formatted(.number.precision(.fractionLength(0...1)))
        return (used, "of \(total) GB")
    }

    /// The total beside the used figure: "of 128 GB", or "/1,024 GB" from 1,000 GB up, where the
    /// long form beside a four-digit figure is wider than the column. Chosen by the total,
    /// which does not change while Tattle runs, so the form does not flip as the used figure
    /// grows.
    private var memoryTotal: String {
        let gigabytes = Double(sample.memory.total) / 1_073_741_824.0
        guard gigabytes >= 1000 else { return memory.total }
        return "/\(gigabytes.formatted(.number.precision(.fractionLength(0...1)))) GB"
    }

    /// The number and its unit, apart: "1.2" and "MB/s".
    private func rate(_ bytesPerSecond: Double) -> (value: String, unit: String) {
        let text = ByteRate.full(bytesPerSecond)
        guard let space = text.lastIndex(of: " ") else { return (text, "") }
        return (String(text[..<space]), String(text[text.index(after: space)...]))
    }
}
