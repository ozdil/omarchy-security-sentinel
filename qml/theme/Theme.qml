pragma Singleton
import QtQuick
import Quickshell
import Quickshell.Io

QtObject {
    id: root

    readonly property string homeDir: Quickshell.env("HOME")
    readonly property string omarchyStateDir: homeDir + "/.local/state/omarchy/current"

    property string themeName: "monotone"
    property bool isDarkTheme: true

    // Dynamic Color Palette
    property color bgDark: "#0a0a0a"
    property color bgBase: "#111111"
    property color bgSurface: "#1a1a1a"
    property color bgCard: "#222222"
    property color bgCardHover: "#2c2c2c"
    property color border: "#333333"
    property color borderLight: "#444444"

    property color textMain: "#e5e5e5"
    property color textMuted: "#888888"
    property color textDim: "#555555"

    property color accent: "#b8b8b8"
    property color accentHover: "#cccccc"
    property color accentSuccess: "#a6da95"
    property color accentWarning: "#eed49f"
    property color accentDanger: "#ed8796"

    readonly property int radiusSm: 4
    readonly property int radiusMd: 8
    readonly property int radiusLg: 12

    readonly property string fontFamily: "JetBrainsMono Nerd Font, JetBrains Mono, monospace"
    readonly property string monoFont: "JetBrainsMono Nerd Font, JetBrains Mono, monospace"
    readonly property string iconFont: "JetBrainsMono Nerd Font, JetBrains Mono, monospace"

    // Themeable Monochrome Icons (Unicode Font Glyph Standard - Zero Emoji Policy)
    readonly property string iconShield: "\uf132"
    readonly property string iconShieldCheck: "\uf3ed"
    readonly property string iconShieldAlert: "\uf3eb"
    readonly property string iconBrain: "\uf5dc"
    readonly property string iconNetwork: "\uf1eb"
    readonly property string iconUsb: "\uf287"
    readonly property string iconLock: "\uf023"
    readonly property string iconUnlock: "\uf09c"
    readonly property string iconCheck: "\uf00c"
    readonly property string iconTimes: "\uf00d"
    readonly property string iconRefresh: "\uf021"
    readonly property string iconSnowflake: "\uf2dc"
    readonly property string iconTrash: "\uf1f8"
    readonly property string iconEye: "\uf06e"

    property string lastLoadedRaw: ""

    function loadColors(raw) {
        if (!raw || raw.trim().length === 0 || raw === lastLoadedRaw) return
        lastLoadedRaw = raw

        var dict = {}
        var lines = String(raw).split("\n")
        for (var i = 0; i < lines.length; i++) {
            var line = lines[i].trim()
            if (!line || line.charAt(0) === '#') continue
            var match = line.match(/^([A-Za-z0-9_-]+)\s*=\s*["']?([^"'\r\n]+?)["']?\s*(?:#.*)?$/)
            if (match) {
                dict[match[1].toLowerCase()] = match[2].trim()
            }
        }

        var mode = dict["mode"] || "dark"
        root.isDarkTheme = (mode !== "light")

        var base = dict["background"] || dict["bg"] || (root.isDarkTheme ? "#111111" : "#f5f5f5")
        var fg = dict["foreground"] || dict["fg"] || (root.isDarkTheme ? "#e5e5e5" : "#1a1a1a")
        var acc = dict["accent"] || dict["color4"] || dict["color6"] || "#b8b8b8"
        var sel = dict["selection"] || dict["selection_background"] || ""
        var mut = dict["muted"] || dict["color8"] || ""

        root.bgBase = base

        if (root.isDarkTheme) {
            root.bgDark = dict["dark_background"] || Qt.darker(base, 1.25)
            root.bgSurface = dict["lighter_background"] || (sel ? sel : Qt.lighter(base, 1.3))
            root.bgCard = (sel && sel !== base) ? sel : Qt.lighter(base, 1.5)
            root.bgCardHover = Qt.lighter(root.bgCard, 1.15)
            root.border = mut ? mut : Qt.rgba(fg.r, fg.g, fg.b, 0.2)
            root.borderLight = Qt.rgba(acc.r, acc.g, acc.b, 0.35)
            root.textMain = dict["bright_foreground"] || fg
            root.textMuted = dict["light_foreground"] || mut || Qt.rgba(fg.r, fg.g, fg.b, 0.65)
            root.textDim = dict["dark_foreground"] || dict["color8"] || Qt.rgba(fg.r, fg.g, fg.b, 0.4)
        } else {
            root.bgDark = Qt.darker(base, 1.08)
            root.bgSurface = Qt.lighter(base, 1.02)
            root.bgCard = Qt.darker(base, 1.04)
            root.bgCardHover = Qt.darker(root.bgCard, 1.06)
            root.border = mut ? mut : Qt.rgba(fg.r, fg.g, fg.b, 0.2)
            root.borderLight = Qt.rgba(acc.r, acc.g, acc.b, 0.35)
            root.textMain = dict["bright_foreground"] || fg
            root.textMuted = dict["light_foreground"] || mut || Qt.rgba(fg.r, fg.g, fg.b, 0.65)
            root.textDim = Qt.rgba(fg.r, fg.g, fg.b, 0.4)
        }

        root.accent = acc
        root.accentHover = Qt.lighter(acc, 1.15)
        root.accentSuccess = dict["bright_green"] || dict["green"] || "#a6da95"
        root.accentWarning = dict["yellow"] || dict["bright_yellow"] || "#eed49f"
        root.accentDanger = dict["red"] || dict["bright_red"] || "#ed8796"
    }

    property FileView colorsFile: FileView {
        id: colorsFile
        path: root.omarchyStateDir + "/theme/colors.toml"
        watchChanges: true
        printErrors: false
        onLoaded: root.loadColors(text())
        onFileChanged: reload()
    }

    property FileView themeNameFile: FileView {
        id: themeNameFile
        path: root.omarchyStateDir + "/theme.name"
        watchChanges: true
        printErrors: false
        onLoaded: {
            var n = text().trim()
            if (n.length > 0 && n !== root.themeName) {
                root.themeName = n
                root.lastLoadedRaw = ""
                colorsFile.reload()
            }
        }
        onFileChanged: {
            reload()
            root.lastLoadedRaw = ""
            colorsFile.reload()
        }
    }
}
