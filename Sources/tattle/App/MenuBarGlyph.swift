import AppKit

/// The menu bar mark: two crossed leaves around a ring. It is drawn here, not loaded from a
/// file, so that it is sharp on any display and takes the menu bar's colour as a template
/// image. Its shapes lie in a 177-unit square. The mark is 16 points across in an 18-point
/// image, the size of the menu bar's other marks.
@MainActor
enum MenuBarGlyph {
    static let eye = image(slashed: false)
    /// Struck through, for a Tattle that failed to start.
    static let slashedEye = image(slashed: true)

    /// The lines' widths in the square's units, heavy enough to hold at 16 points.
    private static let leafLine: CGFloat = 13.8
    private static let ringLine: CGFloat = 15

    private static func image(slashed: Bool) -> NSImage {
        let side: CGFloat = 18
        let image = NSImage(size: NSSize(width: side, height: side), flipped: true) { rect in
            guard let context = NSGraphicsContext.current?.cgContext else { return false }
            // The leaves reach from 6 to 171, and half a line's width past that on each side.
            let scale = 16 / (165 + leafLine)
            context.translateBy(x: rect.midX, y: rect.midY)
            context.scaleBy(x: scale, y: scale)
            context.translateBy(x: -88.5, y: -88.5)
            context.setStrokeColor(.black)
            context.setLineJoin(.round)

            // One leaf from the top left corner to the bottom right, one across it.
            let leaves = CGMutablePath()
            leaves.move(to: CGPoint(x: 6, y: 6))
            leaves.addCurve(to: CGPoint(x: 171, y: 171), control1: CGPoint(x: 113, y: 6), control2: CGPoint(x: 171, y: 64))
            leaves.addCurve(to: CGPoint(x: 6, y: 6), control1: CGPoint(x: 64, y: 171), control2: CGPoint(x: 6, y: 113))
            leaves.closeSubpath()
            leaves.move(to: CGPoint(x: 171, y: 6))
            leaves.addCurve(to: CGPoint(x: 6, y: 171), control1: CGPoint(x: 64, y: 6), control2: CGPoint(x: 6, y: 64))
            leaves.addCurve(to: CGPoint(x: 171, y: 6), control1: CGPoint(x: 113, y: 171), control2: CGPoint(x: 171, y: 113))
            leaves.closeSubpath()
            context.setLineWidth(leafLine)
            context.addPath(leaves)
            context.strokePath()
            context.setLineWidth(ringLine)
            context.strokeEllipse(in: CGRect(x: 88.5 - 32.6, y: 88.5 - 32.6, width: 65.2, height: 65.2))

            if slashed {
                let slash = CGMutablePath()
                slash.move(to: CGPoint(x: 26, y: 19))
                slash.addLine(to: CGPoint(x: 158, y: 151))
                context.setLineCap(.round)
                // A wider clear stroke first, so a gap separates the slash from the mark.
                context.setBlendMode(.clear)
                context.setLineWidth(22.5)
                context.addPath(slash)
                context.strokePath()
                context.setBlendMode(.normal)
                context.setLineWidth(12.4)
                context.addPath(slash)
                context.strokePath()
            }
            return true
        }
        image.isTemplate = true
        return image
    }
}
