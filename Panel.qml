import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

Panel {
  id: root
  moduleName: "ozdil.security-sentinel"
  ipcTarget: "ozdil.security-sentinel"
  manageIpc: false

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  property string overallStatus: "ALL SYSTEMS SECURE"
  property string threatLevel: "ZERO"
  property int activeCount: 8
  property var modules: []
  property string expandedId: ""

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color accent: Color.accent
  readonly property color urgent: Color.urgent
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  function resolveEnginePath() {
    return Qt.resolvedUrl("sentinel-engine").toString().replace(/^file:\/\//, "")
  }

  function refresh() {
    if (!stateProc.running) {
      stateProc.running = true
    }
  }

  function toggleExpand(id) {
    expandedId = (expandedId === id ? "" : id)
  }

  function toggleGhostMac() {
    var mods = root.modules
    for (var i = 0; i < mods.length; i++) {
      if (mods[i].id === "ghost_mac") {
        mods[i].toggle_state = !mods[i].toggle_state
        if (mods[i].toggle_state) {
          mods[i].status = "SECURE"
          mods[i].summary = "Randomized (Assigning...)"
        } else {
          mods[i].status = "WARNING"
          mods[i].summary = "Hardware MAC"
        }
        break
      }
    }
    root.modules = [].concat(mods)
    if (!toggleGhostProc.running) {
      toggleGhostProc.running = true
    }
  }

  function toggleDns() {
    var mods = root.modules
    for (var i = 0; i < mods.length; i++) {
      if (mods[i].id === "dns") {
        mods[i].toggle_state = !mods[i].toggle_state
        if (mods[i].toggle_state) {
          mods[i].status = "SECURE"
          mods[i].summary = "DoT Active (Cloudflare)"
        } else {
          mods[i].status = "WARNING"
          mods[i].summary = "Unencrypted ISP DNS (DHCP)"
        }
        break
      }
    }
    root.modules = [].concat(mods)
    if (!toggleDnsProc.running) {
      toggleDnsProc.running = true
    }
  }

  function trustAllUsb() {
    if (!trustUsbProc.running) {
      trustUsbProc.running = true
    }
  }

  function resetCanaries() {
    if (!resetCanariesProc.running) {
      resetCanariesProc.running = true
    }
  }

  function scrubDownloads() {
    actionProc.command = [root.resolveEnginePath(), "--scrub-downloads"]
    actionProc.running = true
  }

  function openFilePicker() {
    if (!pickFileProc.running) {
      pickFileProc.running = true
    }
  }

  function cleanFiles(fileList) {
    if (fileList && fileList.length > 0) {
      var cmd = [root.resolveEnginePath(), "--clean-files"]
      for (var i = 0; i < fileList.length; i++) {
        var f = String(fileList[i] || "").trim().replace(/^file:\/\//, "")
        f = decodeURIComponent(f)
        if (f.length > 0) {
          cmd.push(f)
        }
      }
      if (cmd.length > 2) {
        actionProc.command = cmd
        actionProc.running = true
      }
    }
  }

  function moduleIcon(id) {
    switch (id) {
      case "network": return "󰒃"
      case "badusb": return "󰕓"
      case "cve": return "󰮯"
      case "auth": return "󰌆"
      case "tripwire": return "󰘿"
      case "dns": return "󰖂"
      case "ghost_mac": return "󰤨"
      case "opsec": return "󰄄"
      default: return ""
    }
  }

  IpcHandler {
    target: "ozdil.security-sentinel"
    function open() { root.open() }
    function close() { root.close() }
    function toggle() { root.toggle() }
    function refresh() { root.refresh() }
    function toggleGhostMac() { root.toggleGhostMac() }
    function toggleDns() { root.toggleDns() }
    function expand(id: string) { root.toggleExpand(id) }
  }

  Process {
    id: pickFileProc
    command: ["zenity", "--file-selection", "--multiple", "--file-filter=Images | *.jpg *.jpeg *.png *.JPG *.PNG *.webp", "--title=OpSec: Select Images to Scrub EXIF"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var raw = String(text || "").trim()
        if (raw.length > 0) {
          var files = raw.split("|")
          root.cleanFiles(files)
        }
      }
    }
  }

  Process {
    id: stateProc
    command: [root.resolveEnginePath(), "--json"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var clean = String(text || "").slice(0, 65536)
          var d = JSON.parse(clean)
          root.overallStatus = String(d.overall_status || "ALL SYSTEMS SECURE")
          root.threatLevel = String(d.threat_level || "ZERO")
          root.activeCount = Number(d.active_modules) || 8
          root.modules = d.modules || []
        } catch(e) {}
      }
    }
  }

  Process {
    id: toggleGhostProc
    command: [root.resolveEnginePath(), "--toggle-ghost-mac"]
    onExited: function(code) {
      root.refresh()
    }
  }

  Process {
    id: toggleDnsProc
    command: [root.resolveEnginePath(), "--toggle-dns"]
    onExited: function(code) {
      root.refresh()
    }
  }

  Process {
    id: trustUsbProc
    command: [root.resolveEnginePath(), "--trust-all-usb"]
    onExited: function(code) {
      root.refresh()
    }
  }

  Process {
    id: resetCanariesProc
    command: [root.resolveEnginePath(), "--reset-canaries"]
    onExited: function(code) {
      root.refresh()
    }
  }

  Process {
    id: actionProc
    onExited: function(code) {
      root.refresh()
    }
  }

  Timer {
    interval: 20000
    running: true
    repeat: true
    triggeredOnStart: true
    onTriggered: root.refresh()
  }

  Component.onCompleted: refresh()
  Component.onDestruction: {
    if (stateProc.running) stateProc.running = false
    if (toggleGhostProc.running) toggleGhostProc.running = false
    if (toggleDnsProc.running) toggleDnsProc.running = false
    if (trustUsbProc.running) trustUsbProc.running = false
    if (resetCanariesProc.running) resetCanariesProc.running = false
    if (actionProc.running) actionProc.running = false
    if (pickFileProc.running) pickFileProc.running = false
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: ""
    tooltipText: "Security Sentinel Hub\nStatus: " + root.overallStatus + "\nThreat: " + root.threatLevel
    onPressed: function(b) {
      root.toggle()
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    contentWidth: panel.fittedContentWidth(Style.space(500))
    contentHeight: panel.fittedContentHeight(panelColumn.implicitHeight)

    DropArea {
      id: dropArea
      anchors.fill: parent
      onEntered: function(drag) {
        if (drag.hasUrls) drag.acceptProposedAction()
      }
      onDropped: function(drop) {
        if (drop.hasUrls) {
          var files = []
          for (var i = 0; i < drop.urls.length; i++) {
            var urlStr = drop.urls[i].toString()
            var localPath = urlStr.replace(/^file:\/\//, "")
            files.push(decodeURIComponent(localPath))
          }
          if (files.length > 0) {
            root.cleanFiles(files)
          }
        }
      }
    }

    Column {
      id: panelColumn
      width: parent.width
      spacing: Style.space(12)

      // ---------- Hero: Shield icon · title/status ----------
      Item {
        width: parent.width
        implicitHeight: Math.max(heroIcon.implicitHeight, heroLabels.implicitHeight)

        Text {
          id: heroIcon
          textFormat: Text.PlainText
          text: ""
          color: root.threatLevel === "ZERO" ? (root.bar ? root.bar.foreground : Color.foreground) : (root.threatLevel === "CRITICAL" ? Color.urgent : "#f59e0b")
          font.family: root.fontFamily
          font.pixelSize: Style.font.display
          anchors.left: parent.left
          anchors.verticalCenter: parent.verticalCenter
        }

        Column {
          id: heroLabels
          anchors.left: heroIcon.right
          anchors.leftMargin: Style.space(14)
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          spacing: Style.space(2)

          Text {
            text: "Security Sentinel"
            color: root.foreground
            font.family: root.fontFamily
            font.pixelSize: Style.font.title
            font.bold: true
            elide: Text.ElideRight
            width: parent.width
          }

          Text {
            textFormat: Text.PlainText
            text: root.overallStatus.toUpperCase()
            color: root.threatLevel === "ZERO" ? Qt.darker(root.foreground, 1.4) : (root.threatLevel === "CRITICAL" ? Color.urgent : "#f59e0b")
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            font.bold: true
            font.letterSpacing: 1.2
          }

          Text {
            textFormat: Text.PlainText
            text: "Threat: " + root.threatLevel + " • " + root.activeCount + " Active Subsystems (Click to inspect)"
            color: Qt.darker(root.foreground, 1.6)
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption - 1
          }
        }
      }

      // ---------- Drop Banner (Visible on Drag) ----------
      Rectangle {
        visible: dropArea.containsDrag
        width: parent.width
        height: Style.space(42)
        radius: Style.cornerRadius > 0 ? Style.space(6) : 0
        color: Style.selectedFillFor(root.foreground, root.accent)
        border.color: root.accent
        border.width: 2

        RowLayout {
          anchors.centerIn: parent
          spacing: Style.space(8)

          Text {
            textFormat: Text.PlainText
            text: "📥 Drop images here to strip EXIF & metadata"
            color: root.accent
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            font.bold: true
          }
        }
      }

      // ---------- Subsystems Section ----------
      PanelSeparator {
        foreground: root.foreground
      }

      Column {
        width: parent.width
        spacing: Style.space(6)

        PanelSectionHeader {
          text: "SUBSYSTEMS"
          foreground: root.foreground
          fontFamily: root.fontFamily
        }

        Column {
          width: parent.width
          spacing: Style.space(6)

          Repeater {
            model: root.modules
            delegate: Rectangle {
              id: rowDelegate
              width: parent.width
              implicitHeight: contentCol.implicitHeight + Style.space(16)
              radius: Style.cornerRadius > 0 ? Style.space(6) : 0

              readonly property var modData: modelData
              readonly property string modId: modData ? String(modData.id || "") : ""
              readonly property string modStatus: modData ? String(modData.status || "") : ""
              readonly property var modItems: modData && modData.items ? modData.items : []
              readonly property bool isOpSec: modId === "opsec"
              readonly property bool isToggleable: modData ? Boolean(modData.is_toggleable) : false
              readonly property bool isBadUsbAlert: modId === "badusb" && modStatus === "ALERT"
              readonly property bool isTripwireAlert: modId === "tripwire" && modStatus === "ALERT"
              readonly property bool isAlert: modStatus === "ALERT"
              readonly property bool isWarning: modStatus === "WARNING"
              readonly property bool isExpanded: root.expandedId === modId

              color: isAlert
                     ? Qt.rgba(0.94, 0.27, 0.27, 0.12)
                     : (isWarning
                        ? Qt.rgba(0.96, 0.62, 0.04, 0.08)
                        : (isExpanded
                           ? Qt.darker(Color.popups.background, 0.85)
                           : Style.selectedFillFor(root.foreground, root.accent)))
              border.color: isAlert ? Color.urgent : (isWarning ? "#f59e0b" : (isExpanded ? root.accent : "transparent"))
              border.width: (isAlert || isWarning || isExpanded) ? 1 : 0

              Column {
                id: contentCol
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                anchors.leftMargin: Style.space(12)
                anchors.rightMargin: Style.space(12)
                spacing: Style.space(8)

                // Header Row (Clickable)
                Item {
                  width: parent.width
                  height: headerRow.implicitHeight

                  RowLayout {
                    id: headerRow
                    anchors.fill: parent
                    spacing: Style.space(10)

                    // Module Icon
                    Text {
                      textFormat: Text.PlainText
                      text: root.moduleIcon(rowDelegate.modId)
                      color: rowDelegate.isAlert ? Color.urgent : (rowDelegate.isWarning ? "#f59e0b" : root.accent)
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.title
                      Layout.alignment: Qt.AlignVCenter
                    }

                    // Title & Summary Column
                    ColumnLayout {
                      Layout.fillWidth: true
                      Layout.preferredWidth: 0
                      spacing: Style.space(2)

                      Text {
                        Layout.fillWidth: true
                        textFormat: Text.PlainText
                        text: rowDelegate.modData ? String(rowDelegate.modData.name) : "--"
                        color: root.foreground
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.bodySmall
                        font.bold: true
                        elide: Text.ElideRight
                      }

                      Text {
                        Layout.fillWidth: true
                        textFormat: Text.PlainText
                        text: rowDelegate.modData ? String(rowDelegate.modData.summary) : "--"
                        color: rowDelegate.isAlert ? Color.urgent : (rowDelegate.isWarning ? "#f59e0b" : Qt.darker(root.foreground, 1.45))
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        elide: Text.ElideRight
                      }
                    }

                    // Interactive Control / Status Indicator
                    Loader {
                      id: headerLoader
                      Layout.alignment: Qt.AlignVCenter
                      sourceComponent: {
                        if (rowDelegate.isToggleable) return toggleComp
                        if (rowDelegate.isOpSec) return opsecComp
                        if (rowDelegate.isBadUsbAlert) return badUsbComp
                        if (rowDelegate.isTripwireAlert) return tripwireComp
                        return badgeComp
                      }
                    }

                    // Expand / Collapse Chevron Indicator
                    Item {
                      Layout.alignment: Qt.AlignVCenter
                      implicitWidth: chevronText.implicitWidth + Style.space(8)
                      implicitHeight: chevronText.implicitHeight

                      Text {
                        id: chevronText
                        anchors.centerIn: parent
                        textFormat: Text.PlainText
                        text: rowDelegate.isExpanded ? "" : ""
                        color: rowDelegate.isExpanded ? root.accent : Qt.darker(root.foreground, 1.7)
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.bodySmall
                      }

                      MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: root.toggleExpand(rowDelegate.modId)
                      }
                    }
                  }

                  // Click to expand / collapse for icon and title area
                  MouseArea {
                    anchors.left: parent.left
                    anchors.top: parent.top
                    anchors.bottom: parent.bottom
                    anchors.right: headerLoader.left
                    anchors.rightMargin: Style.space(6)
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.toggleExpand(rowDelegate.modId)
                  }
                }

                // Expanded Details Container
                Column {
                  visible: rowDelegate.isExpanded
                  width: parent.width
                  spacing: Style.space(6)

                  // Subtle Divider
                  Rectangle {
                    width: parent.width
                    height: 1
                    color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.12)
                  }

                  // Subsystem Details List
                  Repeater {
                    model: rowDelegate.modItems
                    delegate: RowLayout {
                      width: parent.width
                      spacing: Style.space(6)

                      Text {
                        textFormat: Text.PlainText
                        text: "•"
                        color: root.accent
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        Layout.alignment: Qt.AlignTop
                      }

                      Text {
                        Layout.fillWidth: true
                        textFormat: Text.PlainText
                        text: String(modelData)
                        color: Qt.darker(root.foreground, 1.25)
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        wrapMode: Text.WrapAnywhere
                      }
                    }
                  }

                  // Contextual In-Card Actions
                  Item {
                    visible: rowDelegate.modId === "badusb" || rowDelegate.modId === "tripwire" || rowDelegate.modId === "opsec"
                    width: parent.width
                    height: (visible ? Style.space(32) : 0)

                    RowLayout {
                      anchors.fill: parent
                      spacing: Style.space(8)

                      Button {
                        visible: rowDelegate.modId === "badusb"
                        text: "Trust All Connected USBs"
                        iconText: ""
                        foreground: root.foreground
                        accent: root.accent
                        fontFamily: root.fontFamily
                        fontSize: Style.font.caption
                        bordered: true
                        onClicked: root.trustAllUsb()
                      }

                      Button {
                        visible: rowDelegate.modId === "tripwire"
                        text: "Reset Honey-token SHA-256"
                        iconText: ""
                        foreground: root.foreground
                        accent: root.accent
                        fontFamily: root.fontFamily
                        fontSize: Style.font.caption
                        bordered: true
                        onClicked: root.resetCanaries()
                      }

                      Button {
                        visible: rowDelegate.modId === "opsec"
                        text: "Pick Files..."
                        iconText: ""
                        foreground: root.foreground
                        accent: root.accent
                        fontFamily: root.fontFamily
                        fontSize: Style.font.caption
                        bordered: true
                        onClicked: root.openFilePicker()
                      }

                      Button {
                        visible: rowDelegate.modId === "opsec"
                        text: "Scrub Downloads"
                        iconText: ""
                        foreground: root.foreground
                        accent: root.accent
                        fontFamily: root.fontFamily
                        fontSize: Style.font.caption
                        bordered: true
                        onClicked: root.scrubDownloads()
                      }
                    }
                  }
                }
              }

              Component {
                id: toggleComp
                ToggleSwitch {
                  checked: rowDelegate.modData ? Boolean(rowDelegate.modData.toggle_state) : false
                  foreground: root.foreground
                  accent: root.accent
                  onToggled: {
                    if (rowDelegate.modId === "ghost_mac") {
                      root.toggleGhostMac()
                    } else if (rowDelegate.modId === "dns") {
                      root.toggleDns()
                    }
                  }
                }
              }

              Component {
                id: opsecComp
                Button {
                  text: "Scrub..."
                  iconText: ""
                  foreground: root.foreground
                  accent: root.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  iconSize: Style.font.bodySmall
                  horizontalPadding: Style.space(8)
                  verticalPadding: Style.space(4)
                  bordered: true
                  onClicked: root.openFilePicker()
                }
              }

              Component {
                id: badUsbComp
                Button {
                  text: "Trust All"
                  foreground: Color.urgent
                  accent: Color.urgent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  horizontalPadding: Style.space(8)
                  verticalPadding: Style.space(4)
                  bordered: true
                  onClicked: root.trustAllUsb()
                }
              }

              Component {
                id: tripwireComp
                Button {
                  text: "Reset"
                  foreground: Color.urgent
                  accent: Color.urgent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  horizontalPadding: Style.space(8)
                  verticalPadding: Style.space(4)
                  bordered: true
                  onClicked: root.resetCanaries()
                }
              }

              Component {
                id: badgeComp
                Rectangle {
                  implicitWidth: badgeText.implicitWidth + Style.space(12)
                  implicitHeight: badgeText.implicitHeight + Style.space(6)
                  radius: Style.cornerRadius > 0 ? Style.space(4) : 0
                  color: rowDelegate.modStatus === "SECURE"
                         ? Qt.rgba(0.13, 0.77, 0.37, 0.15)
                         : (rowDelegate.modStatus === "READY"
                            ? Qt.rgba(0.2, 0.6, 1.0, 0.15)
                            : Qt.rgba(0.96, 0.62, 0.04, 0.15))
                  border.color: rowDelegate.modStatus === "SECURE"
                                ? "#22c55e"
                                : (rowDelegate.modStatus === "READY" ? "#38bdf8" : "#f59e0b")
                  border.width: 1

                  Text {
                    id: badgeText
                    anchors.centerIn: parent
                    textFormat: Text.PlainText
                    text: rowDelegate.modStatus
                    color: parent.border.color
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption - 1
                    font.bold: true
                  }
                }
              }
            }
          }
        }
      }

      // ---------- Actions Section ----------
      PanelSeparator {
        foreground: root.foreground
      }

      Column {
        width: parent.width
        spacing: Style.space(6)

        PanelSectionHeader {
          text: "QUICK ACTIONS"
          foreground: root.foreground
          fontFamily: root.fontFamily
        }

        RowLayout {
          width: parent.width
          spacing: Style.space(8)

          Button {
            Layout.fillWidth: true
            text: "Scrub File..."
            iconText: ""
            foreground: root.foreground
            accent: root.accent
            fontFamily: root.fontFamily
            bordered: true
            onClicked: root.openFilePicker()
          }

          Button {
            Layout.fillWidth: true
            text: "Scrub Downloads"
            iconText: ""
            foreground: root.foreground
            accent: root.accent
            fontFamily: root.fontFamily
            bordered: true
            onClicked: root.scrubDownloads()
          }

          Button {
            Layout.fillWidth: true
            text: "Audit Now"
            iconText: ""
            foreground: root.foreground
            accent: root.accent
            fontFamily: root.fontFamily
            bordered: true
            onClicked: root.refresh()
          }
        }
      }
    }
  }
}
