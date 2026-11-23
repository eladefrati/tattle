import SwiftUI

/// The panel's measures. It sits on the system's glass: rows lie on the window itself, text
/// takes the system's label colours, and controls are glass.
enum PanelLook {
    /// The corner of a card and of a tile.
    static let corner: CGFloat = 12
    /// How far a title sits from a list's edge, so it lines up with what is in the rows.
    static let titleInset: CGFloat = 10
}

/// The panel's colours, each with its light and dark value.
enum PanelColor {
    /// What the panel's pages lie on: a wash of the window's own colour, which keeps text
    /// legible over whatever is behind the glass.
    static let background = Color(nsColor: .windowBackgroundColor).opacity(0.42)
    // Text and fills come from the system's own label colours, which stay legible over
    // whatever shows through the glass.
    static let card = Color.primary.opacity(0.05)
    static let fill = Color.primary.opacity(0.08)
    static let text = Color.primary
    static let sub = Color.secondary
    static let line = Color.primary.opacity(0.1)
    static let accent = dynamic(light: rgb(0x0064E1), dark: rgb(0x4C9BFF))
    static let onAccent = dynamic(light: rgb(0xFFFFFF), dark: rgb(0x06182E))
    static let newBackground = dynamic(light: rgb(0xFFEDD6), dark: rgb(0xFF9F0A, alpha: 0.2))
    static let newText = dynamic(light: rgb(0x9A4A00), dark: rgb(0xFFBE5C))
    static let newDot = dynamic(light: rgb(0xE07800), dark: rgb(0xFF9F0A))
    static let ok = dynamic(light: rgb(0x1F9D4D), dark: rgb(0x30D158))
    static let track = dynamic(light: black(0.14), dark: white(0.18))
    static let bad = dynamic(light: rgb(0xC4271B), dark: rgb(0xFF6B61))

    private static func dynamic(light: NSColor, dark: NSColor) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua ? dark : light
        })
    }

    private static func rgb(_ hex: Int, alpha: CGFloat = 1) -> NSColor {
        NSColor(srgbRed: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255, blue: CGFloat(hex & 0xFF) / 255, alpha: alpha)
    }

    private static func black(_ alpha: CGFloat) -> NSColor { NSColor(srgbRed: 0, green: 0, blue: 0, alpha: alpha) }
    private static func white(_ alpha: CGFloat) -> NSColor { NSColor(srgbRed: 1, green: 1, blue: 1, alpha: alpha) }
}

enum PanelFont {
    /// Row subtitles, section titles, captions.
    static let small = Font.system(size: 11.5)
    static let smallBold = Font.system(size: 11.5, weight: .semibold)
    static let label = Font.system(size: 11)
    static let button = Font.system(size: 12)
    /// The name at the top of a detail page.
    static let title = Font.system(size: 17, weight: .semibold)
}

/// A rounded block that rows and text sit on.
struct Card<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 0) { content }
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(PanelColor.card)
            .clipShape(RoundedRectangle(cornerRadius: PanelLook.corner, style: .continuous))
    }
}

/// The hairline between rows of a card.
struct RowLine: View {
    var body: some View {
        Rectangle().fill(PanelColor.line).frame(height: 1)
    }
}

/// A list's rows. They sit on the glass itself, as a menu's do; the pointer lights one up.
struct CardRows<Item: Identifiable, Row: View>: View {
    let items: [Item]
    @ViewBuilder var row: (Item) -> Row

    var body: some View {
        LazyVStack(alignment: .leading, spacing: 0) {
            ForEach(items) { item in row(item) }
        }
    }
}

/// A row that opens a page: its content, then the arrow. The pointer lights the row up and
/// brings out its arrow.
struct NavRow<Content: View>: View {
    let route: PanelRoute
    @ViewBuilder var content: Content
    @Environment(PanelRouter.self) private var router
    @State private var hovered = false

    var body: some View {
        Button {
            router.push(route)
        } label: {
            HStack(spacing: 10) {
                content
                Image(systemName: "chevron.right")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(PanelColor.sub)
                    .opacity(hovered ? 1 : 0)
                    .accessibilityHidden(true)
            }
            .padding(.leading, 10)
            .padding(.trailing, 8)
            .background {
                if hovered {
                    RoundedRectangle(cornerRadius: 8, style: .continuous).fill(PanelColor.fill)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovered = $0 }
    }
}

/// The title over a card of rows, with an optional line of explanation.
struct SectionTitle: View {
    let title: String
    var description: String?
    var trailing: String?
    var marked = false

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 6) {
                if marked {
                    Circle().fill(PanelColor.newDot).frame(width: 7, height: 7).accessibilityHidden(true)
                }
                Text(title).font(PanelFont.smallBold).accessibilityAddTraits(.isHeader)
                Spacer()
                if let trailing { Text(trailing).font(PanelFont.small) }
            }
            if let description {
                Text(description)
                    .font(PanelFont.small)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .foregroundStyle(PanelColor.sub)
        .padding(.horizontal, PanelLook.titleInset)
    }
}

/// A small rounded word beside a name: "new", or what became of an item that is gone.
struct Pill: View {
    enum Kind { case new, gone }

    let text: String
    var kind = Kind.gone

    var body: some View {
        Text(text)
            .font(.system(size: 11, weight: .medium))
            .lineLimit(1)
            .fixedSize()
            .padding(.horizontal, 7)
            .padding(.vertical, 2)
            .foregroundStyle(kind == .new ? PanelColor.newText : PanelColor.sub)
            .background(kind == .new ? PanelColor.newBackground : PanelColor.fill, in: Capsule())
    }
}

/// The app's icon when the row is an app, else the first letter of its name on a neutral tile.
struct IconTile: View {
    let name: String
    var path: String?
    var size: CGFloat = 24

    var body: some View {
        Group {
            if let icon = Self.icon(path) {
                Image(nsImage: icon).resizable().interpolation(.high)
            } else {
                // A neutral tile with the letter in capitals, or Apple's logo for the macOS row.
                RoundedRectangle(cornerRadius: size / 4, style: .continuous)
                    .fill(PanelColor.fill)
                    .overlay {
                        if name == "macOS" {
                            Image(systemName: "apple.logo")
                                .font(.system(size: size / 2, weight: .medium))
                                .foregroundStyle(PanelColor.sub)
                        } else {
                            Text(name.prefix(1).uppercased())
                                .font(.system(size: size / 2, weight: .semibold, design: .rounded))
                                .foregroundStyle(PanelColor.sub)
                        }
                    }
            }
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }

    @MainActor private static let icons = NSCache<NSString, NSImage>()

    /// Only an app bundle's: a bare program's icon is the same grey sheet for all of them.
    private static func icon(_ path: String?) -> NSImage? {
        guard let path, path.hasSuffix(".app") else { return nil }
        if let cached = icons.object(forKey: path as NSString) { return cached }
        guard FileManager.default.fileExists(atPath: path) else { return nil }
        let icon = NSWorkspace.shared.icon(forFile: path)
        icons.setObject(icon, forKey: path as NSString)
        return icon
    }
}

/// The panel's buttons, each a glass capsule: plain, the main action tinted with the accent
/// colour, a destructive one with red.
struct PanelButtonStyle: ButtonStyle {
    enum Kind { case plain, primary, danger }

    var kind = Kind.plain
    var height: CGFloat = 24
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 12, weight: .medium))
            .lineLimit(1)
            .fixedSize()
            .padding(.horizontal, 12)
            .frame(height: max(height, 26))
            .foregroundStyle(foreground)
            .glassEffect(kind == .plain ? .regular.interactive(isEnabled) : .regular.tint(background).interactive(isEnabled), in: .capsule)
            .opacity(isEnabled ? 1 : 0.45)
    }

    private var foreground: Color {
        switch kind {
        case .plain: PanelColor.text
        case .primary: PanelColor.onAccent
        case .danger: .white
        }
    }

    private var background: Color {
        switch kind {
        case .plain: PanelColor.card
        case .primary: PanelColor.accent
        case .danger: PanelColor.bad
        }
    }
}

extension ButtonStyle where Self == PanelButtonStyle {
    static var panel: PanelButtonStyle { PanelButtonStyle() }
    static var panelPrimary: PanelButtonStyle { PanelButtonStyle(kind: .primary) }
    static var panelDanger: PanelButtonStyle { PanelButtonStyle(kind: .danger) }
}

/// Label and value rows, shared by the detail pages.
struct FactsCard: View {
    let facts: [Fact]

    var body: some View {
        Card {
            ForEach(Array(facts.enumerated()), id: \.offset) { index, fact in
                HStack(alignment: .firstTextBaseline, spacing: 16) {
                    Text(fact.name).foregroundStyle(PanelColor.sub).fixedSize()
                    Spacer(minLength: 0)
                    Text(fact.value)
                        .multilineTextAlignment(.trailing)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(.vertical, 7)
                .padding(.horizontal, 12)
                if index < facts.count - 1 { RowLine().padding(.horizontal, 12) }
            }
        }
    }
}

/// The top of an app's, process's, port's or startup item's page: its icon, its name, what
/// became of it when it is gone, and who signed it.
struct ItemHeader<Trailing: View>: View {
    let name: String
    var path: String?
    var signature: CodeSignature?
    /// Shown beside the name once the item is gone.
    var gone: String?
    @ViewBuilder var trailing: Trailing

    var body: some View {
        HStack(spacing: 12) {
            IconTile(name: name, path: path, size: 44)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 8) {
                    Text(name).font(PanelFont.title).lineLimit(1).truncationMode(.middle)
                    if let gone { Pill(text: gone) }
                }
                if let signature { SignedLine(signature: signature) }
            }
            Spacer(minLength: 0)
            trailing
        }
        .padding(.horizontal, 4)
    }
}

extension ItemHeader where Trailing == EmptyView {
    init(name: String, path: String? = nil, signature: CodeSignature? = nil, gone: String? = nil) {
        self.init(name: name, path: path, signature: signature, gone: gone) { EmptyView() }
    }
}

/// Who signed a program, with a shield that is green only for a signer Apple vouches for.
struct SignedLine: View {
    let signature: CodeSignature

    var body: some View {
        HStack(spacing: 5) {
            Image(systemName: signature.isVouchedFor ? "checkmark.shield" : "shield.slash")
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(signature.isVouchedFor ? PanelColor.ok : PanelColor.sub)
                .accessibilityHidden(true)
            Text(signature.signedLine).font(PanelFont.button).foregroundStyle(PanelColor.sub).lineLimit(1)
        }
    }
}

extension CodeSignature {
    /// Whether the signature names who made the code that runs, which is what the green shield
    /// says. Apple's on a file outside macOS names Apple and does not say that
    /// (`appleElsewhere`).
    var isVouchedFor: Bool { namesSigner && signer != .appleElsewhere }

    /// The line under a name on a detail page.
    var signedLine: String {
        "Signed by \(summary)" + (teamIdentifier.map { " \u{00B7} Team \($0)" } ?? "")
    }
}

/// A detail page: the bar with the way back and the title, what scrolls, and the buttons that
/// stay put under it.
struct DetailPage<Trailing: View, Content: View, Bar: View>: View {
    let title: String
    @ViewBuilder var trailing: Trailing
    @ViewBuilder var content: Content
    @ViewBuilder var bar: Bar
    @Environment(PanelRouter.self) private var router

    var body: some View {
        VStack(spacing: 0) {
            ZStack {
                // Clear of the way back on both sides, so the title stays centred: the chevron
                // is 28 wide, and a gap.
                Text(title).fontWeight(.semibold).lineLimit(1).truncationMode(.middle)
                    .padding(.horizontal, 36)
                HStack {
                    Button {
                        router.pop()
                    } label: {
                        Image(systemName: "chevron.left")
                            .font(.system(size: 12, weight: .semibold))
                            .frame(width: 28, height: 28)
                            .glassEffect(.regular.interactive(), in: .circle)
                            .contentShape(Circle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Back")
                    Spacer()
                    trailing
                }
            }
            .padding(.horizontal, 12)
            .frame(height: 48)
            ScrollView {
                VStack(alignment: .leading, spacing: 12) { content }
                    .padding(.horizontal, 12)
                    .padding(.top, 14)
                    .padding(.bottom, 12)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            bar
        }
    }
}

extension DetailPage where Trailing == EmptyView {
    init(title: String, @ViewBuilder content: () -> Content, @ViewBuilder bar: () -> Bar) {
        self.init(title: title, trailing: { EmptyView() }, content: content, bar: bar)
    }
}

/// The buttons that stay put at the bottom of a detail page, with a line under them for a
/// note or for what went wrong.
struct ActionBar<Left: View, Right: View>: View {
    var note: String?
    var error: String?
    @ViewBuilder var left: Left
    @ViewBuilder var right: Right

    var body: some View {
        VStack(spacing: 0) {
            RowLine()
            VStack(alignment: .trailing, spacing: 6) {
                HStack(spacing: 8) {
                    left
                    Spacer(minLength: 8)
                    right
                }
                if let note {
                    Text(note).font(PanelFont.small).foregroundStyle(PanelColor.sub)
                }
                if let error {
                    Text(error)
                        .font(PanelFont.small)
                        .foregroundStyle(PanelColor.bad)
                        .multilineTextAlignment(.trailing)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
        }
        .buttonStyle(.panel)
    }
}

/// Shows a file in the Finder.
struct RevealButton: View {
    var title = "Reveal in Finder"
    let path: String

    var body: some View {
        Button(title) { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)]) }
            .buttonStyle(.panel)
    }
}

/// What a list shows before its first reading, or when it could not be read at all.
struct ListPlaceholder: View {
    var loading: String?
    var error: String?

    var body: some View {
        VStack(spacing: 8) {
            if let error {
                Text(error).foregroundStyle(PanelColor.sub).multilineTextAlignment(.center).textSelection(.enabled)
            } else if let loading {
                ProgressView().controlSize(.small)
                Text(loading).font(PanelFont.small).foregroundStyle(PanelColor.sub)
            }
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
