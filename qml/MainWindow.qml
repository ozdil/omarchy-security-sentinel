import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import Quickshell
import Quickshell.Io
import "theme"

Item {
    id: root

    property string threatLevel: "NORMAL"
    property var modules: []
    property var anomalousProcesses: []
    property var selectedModule: null
    property bool networkBlackoutActive: false
    property bool usbArmorEnabled: false
    property string selfIntegrityHash: ""

    readonly property string enginePath: {
        var base = Qt.resolvedUrl(".").toString().replace(/^file:\/\//, "");
        var parent = base.replace(/\/qml\/?$/, "");
        return parent + "/sentinel-engine";
    }

    function refresh() {
        if (!sentinelProc.running) {
            sentinelProc.running = true;
        }
    }

    function toggleBlackout() {
        if (root.networkBlackoutActive) {
            actionProc.command = [root.enginePath, "--resume-network"];
        } else {
            actionProc.command = [root.enginePath, "--panic-blackout"];
        }
        actionProc.running = true;
    }

    function toggleUsbArmor() {
        actionProc.command = [root.enginePath, "--toggle-usb-armor"];
        actionProc.running = true;
    }

    function freezePid(pid) {
        actionProc.command = [root.enginePath, "--kernel-freeze", String(pid)];
        actionProc.running = true;
    }

    function terminatePid(pid) {
        actionProc.command = [root.enginePath, "--kernel-terminate", String(pid)];
        actionProc.running = true;
    }

    function toggleDot() {
        actionProc.command = [root.enginePath, "--toggle-dns"];
        actionProc.running = true;
    }

    function toggleGhostMac() {
        actionProc.command = [root.enginePath, "--toggle-ghost-mac"];
        actionProc.running = true;
    }

    function trustAllUsb() {
        actionProc.command = [root.enginePath, "--trust-all-usb"];
        actionProc.running = true;
    }

    function resetCanaries() {
        actionProc.command = [root.enginePath, "--reset-canaries"];
        actionProc.running = true;
    }

    function scrubDownloads() {
        actionProc.command = [root.enginePath, "--scrub-downloads"];
        actionProc.running = true;
    }

    Process {
        id: sentinelProc
        command: [root.enginePath, "--json"]
        stdout: StdioCollector {
            waitForEnd: true
            onStreamFinished: {
                try {
                    var data = JSON.parse(text || "{}");
                    root.threatLevel = data.threat_level || "ZERO";
                    root.modules = data.modules || [];
                    root.anomalousProcesses = data.ai_anomalies || data.anomalous_processes || [];
                    root.networkBlackoutActive = !!data.network_blackout_active;
                    root.usbArmorEnabled = !!data.usb_armor_enabled;
                    root.selfIntegrityHash = data.self_integrity_hash || "";

                    if (!root.selectedModule && root.modules.length > 0) {
                        root.selectedModule = root.modules[0];
                    } else if (root.selectedModule) {
                        for (var i = 0; i < root.modules.length; i++) {
                            if (root.modules[i].id === root.selectedModule.id) {
                                root.selectedModule = root.modules[i];
                                break;
                            }
                        }
                    }
                } catch(e) {
                    console.warn("Failed to parse sentinel json:", e);
                }
            }
        }
    }

    Process {
        id: actionProc
        onExited: root.refresh()
    }

    Component.onCompleted: refresh()

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 16
        spacing: 14

        // Header Bar
        Rectangle {
            Layout.fillWidth: true
            height: 68
            radius: Theme.radiusMd
            color: Theme.bgSurface
            border.color: Theme.border
            border.width: 1

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: 16
                anchors.rightMargin: 16
                spacing: 12

                Text {
                    text: root.threatLevel === "CRITICAL" ? Theme.iconShieldAlert : (root.threatLevel === "ELEVATED" ? Theme.iconShield : Theme.iconShieldCheck)
                    font.family: Theme.iconFont
                    font.pixelSize: 24
                    color: root.threatLevel === "CRITICAL" ? Theme.accentDanger : (root.threatLevel === "ELEVATED" ? Theme.accentWarning : Theme.accentSuccess)
                }

                ColumnLayout {
                    spacing: 2
                    Text {
                        text: "SECURITY SENTINEL HUB"
                        font.family: Theme.fontFamily
                        font.pixelSize: 15
                        font.bold: true
                        color: Theme.textMain
                    }
                    Text {
                        text: "Kernel Hardening, AI Threat Heuristics & Host Intrusion Shield"
                        font.family: Theme.fontFamily
                        font.pixelSize: 11
                        color: Theme.textMuted
                    }
                }

                Item { Layout.fillWidth: true }

                // Self-Integrity Badge
                Rectangle {
                    height: 32
                    implicitWidth: integrityRow.implicitWidth + 20
                    radius: Theme.radiusSm
                    color: Theme.bgCard
                    border.color: Theme.border
                    border.width: 1

                    RowLayout {
                        id: integrityRow
                        anchors.centerIn: parent
                        spacing: 6

                        Text {
                            text: Theme.iconLock
                            font.family: Theme.iconFont
                            font.pixelSize: 11
                            color: Theme.accentSuccess
                        }

                        Text {
                            text: "INTEGRITY: " + (root.selfIntegrityHash && root.selfIntegrityHash !== "UNVERIFIED" ? "VERIFIED (" + root.selfIntegrityHash.substring(0, 8) + ")" : "UNVERIFIED")
                            font.family: Theme.monoFont
                            font.pixelSize: 11
                            font.bold: true
                            color: Theme.textMain
                        }
                    }
                }

                // Panic Blackout Button
                Rectangle {
                    height: 32
                    implicitWidth: blackoutRow.implicitWidth + 20
                    radius: Theme.radiusSm
                    color: root.networkBlackoutActive ? Theme.accentDanger : (blackoutArea.containsMouse ? Theme.bgCardHover : Theme.bgCard)
                    border.color: root.networkBlackoutActive ? Theme.accentDanger : Theme.accentWarning
                    border.width: 1

                    RowLayout {
                        id: blackoutRow
                        anchors.centerIn: parent
                        spacing: 6

                        Text {
                            text: root.networkBlackoutActive ? Theme.iconShieldAlert : Theme.iconShield
                            font.family: Theme.iconFont
                            font.pixelSize: 12
                            color: root.networkBlackoutActive ? "#ffffff" : Theme.accentWarning
                        }

                        Text {
                            text: root.networkBlackoutActive ? "RESUME NETWORK" : "PANIC BLACKOUT"
                            font.family: Theme.fontFamily
                            font.pixelSize: 11
                            font.bold: true
                            color: root.networkBlackoutActive ? "#ffffff" : Theme.textMain
                        }
                    }

                    MouseArea {
                        id: blackoutArea
                        anchors.fill: parent
                        hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        onClicked: root.toggleBlackout()
                    }
                }

                // Threat Level Pill
                Rectangle {
                    height: 32
                    implicitWidth: threatPillRow.implicitWidth + 20
                    radius: Theme.radiusSm
                    color: Theme.bgCard
                    border.color: Theme.border
                    border.width: 1

                    RowLayout {
                        id: threatPillRow
                        anchors.centerIn: parent
                        spacing: 8

                        Rectangle {
                            width: 8
                            height: 8
                            radius: 4
                            color: root.threatLevel === "CRITICAL" ? Theme.accentDanger : (root.threatLevel === "ELEVATED" ? Theme.accentWarning : Theme.accentSuccess)
                        }

                        Text {
                            text: "THREAT: " + root.threatLevel
                            font.family: Theme.monoFont
                            font.pixelSize: 11
                            font.bold: true
                            color: Theme.textMain
                        }
                    }
                }

                // Refresh Button
                Rectangle {
                    width: 36
                    height: 36
                    radius: Theme.radiusSm
                    color: refreshArea.containsMouse ? Theme.bgCardHover : Theme.bgCard
                    border.color: Theme.border
                    border.width: 1

                    Text {
                        anchors.centerIn: parent
                        text: Theme.iconRefresh
                        font.family: Theme.iconFont
                        font.pixelSize: 14
                        color: Theme.textMain
                    }

                    MouseArea {
                        id: refreshArea
                        anchors.fill: parent
                        hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        onClicked: root.refresh()
                    }
                }
            }
        }

        // Main Layout: Subsystems List (Left) + Detail & Process Monitor (Right)
        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 14

            // Left Column: 9 Subsystem Modules
            Rectangle {
                Layout.preferredWidth: 380
                Layout.fillHeight: true
                radius: Theme.radiusMd
                color: Theme.bgSurface
                border.color: Theme.border
                border.width: 1

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 14
                    spacing: 10

                    Text {
                        text: "ACTIVE SECURITY DEFENSE SUBSYSTEMS"
                        font.family: Theme.fontFamily
                        font.pixelSize: 11
                        font.bold: true
                        font.letterSpacing: 1.0
                        color: Theme.textMuted
                    }

                    ListView {
                        id: modListView
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        clip: true
                        spacing: 6
                        model: root.modules

                        delegate: Rectangle {
                            width: modListView.width
                            height: 54
                            radius: Theme.radiusSm
                            color: root.selectedModule && root.selectedModule.id === modelData.id ? Theme.bgCardHover : Theme.bgCard
                            border.color: root.selectedModule && root.selectedModule.id === modelData.id ? Theme.accent : Theme.border
                            border.width: 1

                            MouseArea {
                                anchors.fill: parent
                                cursorShape: Qt.PointingHandCursor
                                onClicked: root.selectedModule = modelData
                            }

                            RowLayout {
                                anchors.fill: parent
                                anchors.margins: 10
                                spacing: 10

                                Text {
                                    text: modelData.status === "WARNING" ? Theme.iconShieldAlert : Theme.iconShieldCheck
                                    font.family: Theme.iconFont
                                    font.pixelSize: 16
                                    color: modelData.status === "WARNING" ? Theme.accentWarning : Theme.accentSuccess
                                }

                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 2

                                    Text {
                                        Layout.fillWidth: true
                                        text: modelData.name || ""
                                        font.family: Theme.fontFamily
                                        font.pixelSize: 11
                                        font.bold: true
                                        color: Theme.textMain
                                        elide: Text.ElideRight
                                    }

                                    Text {
                                        Layout.fillWidth: true
                                        text: modelData.summary || ""
                                        font.family: Theme.monoFont
                                        font.pixelSize: 10
                                        color: Theme.textMuted
                                        elide: Text.ElideRight
                                    }
                                }

                                Rectangle {
                                    height: 18
                                    implicitWidth: modStatusText.implicitWidth + 8
                                    radius: 3
                                    color: Theme.bgDark
                                    Text {
                                        id: modStatusText
                                        anchors.centerIn: parent
                                        text: modelData.status || "OK"
                                        font.family: Theme.monoFont
                                        font.pixelSize: 9
                                        color: modelData.status === "WARNING" ? Theme.accentWarning : Theme.accentSuccess
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Right Column: Module Details & Process Telemetry
            Rectangle {
                Layout.fillWidth: true
                Layout.fillHeight: true
                radius: Theme.radiusMd
                color: Theme.bgSurface
                border.color: Theme.border
                border.width: 1

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 16
                    spacing: 12
                    visible: root.selectedModule !== null

                    // Header for Selected Module
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: 8

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 2
                            Text {
                                text: root.selectedModule ? root.selectedModule.name : ""
                                font.family: Theme.fontFamily
                                font.pixelSize: 15
                                font.bold: true
                                color: Theme.textMain
                            }
                            Text {
                                text: root.selectedModule ? root.selectedModule.detail : ""
                                font.family: Theme.fontFamily
                                font.pixelSize: 11
                                color: Theme.textMuted
                            }
                        }

                        // Specific Subsystem Controls (DoT, Ghost MAC)
                        Rectangle {
                            height: 30
                            implicitWidth: dotBtnRow.implicitWidth + 16
                            radius: Theme.radiusSm
                            visible: root.selectedModule && root.selectedModule.id === "dns"
                            color: Theme.bgCard
                            border.color: Theme.border
                            border.width: 1

                            RowLayout {
                                id: dotBtnRow
                                anchors.centerIn: parent
                                spacing: 6
                                Text { text: Theme.iconLock; font.family: Theme.iconFont; font.pixelSize: 11; color: Theme.accentSuccess }
                                Text { text: "Toggle DNS-over-TLS"; font.family: Theme.fontFamily; font.pixelSize: 11; color: Theme.textMain }
                            }

                            MouseArea {
                                anchors.fill: parent
                                cursorShape: Qt.PointingHandCursor
                                onClicked: root.toggleDot()
                            }
                        }

                        Rectangle {
                            height: 30
                            implicitWidth: macBtnRow.implicitWidth + 16
                            radius: Theme.radiusSm
                            visible: root.selectedModule && root.selectedModule.id === "ghost_mac"
                            color: Theme.bgCard
                            border.color: Theme.border
                            border.width: 1

                            RowLayout {
                                id: macBtnRow
                                anchors.centerIn: parent
                                spacing: 6
                                Text { text: Theme.iconNetwork; font.family: Theme.iconFont; font.pixelSize: 11; color: Theme.accentWarning }
                                Text { text: "Randomize Wi-Fi MAC"; font.family: Theme.fontFamily; font.pixelSize: 11; color: Theme.textMain }
                            }

                            MouseArea {
                                anchors.fill: parent
                                cursorShape: Qt.PointingHandCursor
                                onClicked: root.toggleGhostMac()
                            }
                        }

                        Rectangle {
                            height: 30
                            implicitWidth: usbArmorBtnRow.implicitWidth + 16
                            radius: Theme.radiusSm
                            visible: root.selectedModule && root.selectedModule.id === "badusb"
                            color: root.usbArmorEnabled ? Theme.accentSuccess : Theme.bgCard
                            border.color: root.usbArmorEnabled ? Theme.accentSuccess : Theme.border
                            border.width: 1

                            RowLayout {
                                id: usbArmorBtnRow
                                anchors.centerIn: parent
                                spacing: 6
                                Text { 
                                    text: Theme.iconShield
                                    font.family: Theme.iconFont
                                    font.pixelSize: 11
                                    color: root.usbArmorEnabled ? Theme.bgDark : Theme.accentSuccess 
                                }
                                Text { 
                                    text: root.usbArmorEnabled ? "USB Armor: ACTIVE" : "Enable USB Armor"
                                    font.family: Theme.fontFamily
                                    font.pixelSize: 11
                                    font.bold: true
                                    color: root.usbArmorEnabled ? Theme.bgDark : Theme.textMain 
                                }
                            }

                            MouseArea {
                                anchors.fill: parent
                                cursorShape: Qt.PointingHandCursor
                                onClicked: root.toggleUsbArmor()
                            }
                        }

                        Rectangle {
                            height: 30
                            implicitWidth: usbBtnRow.implicitWidth + 16
                            radius: Theme.radiusSm
                            visible: root.selectedModule && root.selectedModule.id === "badusb"
                            color: Theme.bgCard
                            border.color: Theme.border
                            border.width: 1

                            RowLayout {
                                id: usbBtnRow
                                anchors.centerIn: parent
                                spacing: 6
                                Text { text: Theme.iconUsb; font.family: Theme.iconFont; font.pixelSize: 11; color: Theme.accentSuccess }
                                Text { text: "Trust All Connected USBs"; font.family: Theme.fontFamily; font.pixelSize: 11; color: Theme.textMain }
                            }

                            MouseArea {
                                anchors.fill: parent
                                cursorShape: Qt.PointingHandCursor
                                onClicked: root.trustAllUsb()
                            }
                        }

                        Rectangle {
                            height: 30
                            implicitWidth: tripBtnRow.implicitWidth + 16
                            radius: Theme.radiusSm
                            visible: root.selectedModule && root.selectedModule.id === "tripwire"
                            color: Theme.bgCard
                            border.color: Theme.border
                            border.width: 1

                            RowLayout {
                                id: tripBtnRow
                                anchors.centerIn: parent
                                spacing: 6
                                Text { text: Theme.iconShield; font.family: Theme.iconFont; font.pixelSize: 11; color: Theme.accentWarning }
                                Text { text: "Reset Canary SHA-256"; font.family: Theme.fontFamily; font.pixelSize: 11; color: Theme.textMain }
                            }

                            MouseArea {
                                anchors.fill: parent
                                cursorShape: Qt.PointingHandCursor
                                onClicked: root.resetCanaries()
                            }
                        }

                        Rectangle {
                            height: 30
                            implicitWidth: opsecBtnRow.implicitWidth + 16
                            radius: Theme.radiusSm
                            visible: root.selectedModule && root.selectedModule.id === "opsec"
                            color: Theme.bgCard
                            border.color: Theme.border
                            border.width: 1

                            RowLayout {
                                id: opsecBtnRow
                                anchors.centerIn: parent
                                spacing: 6
                                Text { text: Theme.iconTrash; font.family: Theme.iconFont; font.pixelSize: 11; color: Theme.accentDanger }
                                Text { text: "Scrub Downloads"; font.family: Theme.fontFamily; font.pixelSize: 11; color: Theme.textMain }
                            }

                            MouseArea {
                                anchors.fill: parent
                                cursorShape: Qt.PointingHandCursor
                                onClicked: root.scrubDownloads()
                            }
                        }
                    }

                    Rectangle {
                        Layout.fillWidth: true
                        height: 1
                        color: Theme.border
                    }

                    // Process Threat Alerts (Shown if AI Behavior module selected)
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 6
                        visible: root.selectedModule && root.selectedModule.id === "ai_behavior" && root.anomalousProcesses.length > 0

                        Text {
                            text: "HEURISTIC SUSPICIOUS PROCESS TELEMETRY"
                            font.family: Theme.fontFamily
                            font.pixelSize: 11
                            font.bold: true
                            font.letterSpacing: 1.0
                            color: Theme.accentWarning
                        }

                        Repeater {
                            model: root.anomalousProcesses
                            delegate: Rectangle {
                                Layout.fillWidth: true
                                height: 50
                                radius: Theme.radiusSm
                                color: Theme.bgCard
                                border.color: Theme.border
                                border.width: 1

                                RowLayout {
                                    anchors.fill: parent
                                    anchors.margins: 10
                                    spacing: 10

                                    Text {
                                        text: "PID " + modelData.pid + " • " + (modelData.name || "")
                                        font.family: Theme.monoFont
                                        font.pixelSize: 11
                                        font.bold: true
                                        color: Theme.textMain
                                    }

                                    Text {
                                        Layout.fillWidth: true
                                        text: modelData.reasons ? modelData.reasons.join(", ") : ""
                                        font.family: Theme.fontFamily
                                        font.pixelSize: 11
                                        color: Theme.textMuted
                                        elide: Text.ElideRight
                                    }

                                    // Freeze Action
                                    Rectangle {
                                        height: 26
                                        implicitWidth: freezeText.implicitWidth + 12
                                        radius: 3
                                        color: freezeArea.containsMouse ? Theme.bgCardHover : Theme.bgDark
                                        border.color: Theme.border
                                        border.width: 1

                                        RowLayout {
                                            anchors.centerIn: parent
                                            spacing: 4
                                            Text { text: Theme.iconSnowflake; font.family: Theme.iconFont; font.pixelSize: 10; color: Theme.accent }
                                            Text { id: freezeText; text: "Freeze"; font.family: Theme.fontFamily; font.pixelSize: 10; color: Theme.textMain }
                                        }

                                        MouseArea {
                                            id: freezeArea
                                            anchors.fill: parent
                                            cursorShape: Qt.PointingHandCursor
                                            onClicked: root.freezePid(modelData.pid)
                                        }
                                    }

                                    // Terminate Action
                                    Rectangle {
                                        height: 26
                                        implicitWidth: termText.implicitWidth + 12
                                        radius: 3
                                        color: termArea.containsMouse ? Theme.bgCardHover : Theme.bgDark
                                        border.color: Theme.border
                                        border.width: 1

                                        RowLayout {
                                            anchors.centerIn: parent
                                            spacing: 4
                                            Text { text: Theme.iconTrash; font.family: Theme.iconFont; font.pixelSize: 10; color: Theme.accentDanger }
                                            Text { id: termText; text: "Kill"; font.family: Theme.fontFamily; font.pixelSize: 10; color: Theme.accentDanger }
                                        }

                                        MouseArea {
                                            id: termArea
                                            anchors.fill: parent
                                            cursorShape: Qt.PointingHandCursor
                                            onClicked: root.terminatePid(modelData.pid)
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Module Telemetry Items List
                    ListView {
                        id: itemsListView
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        clip: true
                        spacing: 6
                        model: (root.selectedModule && root.selectedModule.items) ? root.selectedModule.items : []

                        delegate: Rectangle {
                            width: itemsListView.width
                            height: 36
                            radius: Theme.radiusSm
                            color: Theme.bgCard
                            border.color: Theme.border
                            border.width: 1

                            RowLayout {
                                anchors.fill: parent
                                anchors.leftMargin: 12
                                anchors.rightMargin: 12
                                spacing: 8

                                Text {
                                    text: Theme.iconCheck
                                    font.family: Theme.iconFont
                                    font.pixelSize: 10
                                    color: Theme.accent
                                }

                                Text {
                                    Layout.fillWidth: true
                                    text: modelData
                                    font.family: Theme.monoFont
                                    font.pixelSize: 11
                                    color: Theme.textMain
                                    elide: Text.ElideRight
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
