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

  // Fail closed: until a valid report arrives the widget says so, never "secure"
  property string overallStatus: "ENGINE OFFLINE"
  property string threatLevel: "UNKNOWN"
  property int activeCount: 0
  // Date.now() of the last report that parsed; 0 = none yet
  property double lastReportAt: 0
  // Why the last report could not be used, shown in the panel
  property string engineError: "Waiting for the first report"
  // Result of the last action that failed (engine message), cleared on the next one
  property string actionError: ""
  readonly property int reportStaleSec: 90
  readonly property bool engineDown: root.threatLevel === "UNKNOWN"
  property int aiThreatScore: 0
  property var aiAnomalies: []
  property var kernelCapabilities: []
  property var modules: []
  property string expandedId: ""
  property bool showAboutModal: false
  property int selectedIndex: 0
  property bool cursorActive: false

  readonly property string manifestPath: Qt.resolvedUrl("manifest.json").toString().replace(/^file:\/\//, "")
  readonly property string manifestFallbackPath: Quickshell.env("HOME") ? Quickshell.env("HOME") + "/.config/omarchy/plugins/ozdil.security-sentinel/manifest.json" : ""

  property string pluginName: "Security Sentinel"
  property string pluginVersion: "1.4.0"
  property string pluginDescription: "Unified cyber security sentinel for Omarchy Linux: BadUSB hardware guard, kernel integrity auditor, and zero-trust privacy monitor."
  property string pluginAuthor: "Ozan Özdil"
  property string pluginLicense: "MIT"

  function loadManifest(rawJson) {
    try {
      if (!rawJson || String(rawJson).trim() === "") return
      var parsed = JSON.parse(rawJson)
      if (parsed.name) root.pluginName = parsed.name
      if (parsed.version) root.pluginVersion = parsed.version
      if (parsed.description) root.pluginDescription = parsed.description
      if (parsed.author) root.pluginAuthor = parsed.author
      if (parsed.license) root.pluginLicense = parsed.license
    } catch(e) {}
  }

  FileView {
    id: manifestWatcher
    path: root.manifestPath
    watchChanges: true
    atomicWrites: true
    printErrors: false
    onLoaded: root.loadManifest(text())
    onLoadFailed: {
      manifestFallbackWatcher.reload()
    }
    onFileChanged: reload()
  }

  FileView {
    id: manifestFallbackWatcher
    path: root.manifestFallbackPath
    watchChanges: true
    atomicWrites: true
    printErrors: false
    onLoaded: root.loadManifest(text())
    onFileChanged: reload()
  }

  onOpenedChanged: {
    if (opened) {
      selectedIndex = 0
      cursorActive = false
    }
  }

  function moveCursor(dy) {
    if (!cursorActive) {
      cursorActive = true
      selectedIndex = 0
      return
    }
    var len = root.modules ? root.modules.length : 0
    if (len === 0) return
    var next = selectedIndex + dy
    if (next < 0) next = 0
    if (next >= len) next = len - 1
    selectedIndex = next
  }

  function activateSelected() {
    if (!root.modules || root.modules.length === 0) return
    var mod = root.modules[selectedIndex]
    if (!mod) return
    if (mod.is_toggleable) {
      if (mod.id === "ghost_mac") root.toggleGhostMac()
      else if (mod.id === "dns") root.toggleDns()
      else if (mod.id === "badusb") root.toggleUsbArmor()
    } else {
      root.toggleExpand(mod.id)
    }
  }

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color dim: Qt.darker(foreground, 1.45)
  readonly property color accent: Color.accent
  readonly property color urgent: Color.urgent
  readonly property string fontFamily: (bar && bar.fontFamily) ? bar.fontFamily : ((typeof Style !== "undefined" && Style.font && Style.font.family) ? Style.font.family : "JetBrainsMono Nerd Font, JetBrains Mono, monospace")

  function resolveEnginePath() {
    return Qt.resolvedUrl("sentinel-engine").toString().replace(/^file:\/\//, "")
  }

  // Actions share one Process; queue them so a second click while the first
  // (e.g. a pkexec prompt) is still running is not silently dropped.
  property var actionQueue: []

  function runAction(cmd) {
    root.actionQueue = root.actionQueue.concat([cmd])
    root.startNextAction()
  }

  function startNextAction() {
    if (actionProc.running || root.actionQueue.length === 0) return
    actionProc.command = root.actionQueue[0]
    root.actionQueue = root.actionQueue.slice(1)
    actionProc.running = true
  }

  // The engine daemon keeps this report fresh (and reacts to USB hot-plug
  // within a second); a full --json scan only runs when the cache is stale.
  readonly property string runtimeDir: Quickshell.env("XDG_RUNTIME_DIR") || ""
  readonly property string reportCachePath: runtimeDir !== "" ? runtimeDir + "/omarchy-security-sentinel/report.json" : ""
  readonly property int reportMaxAgeSec: 60

  // The engine caps its report well below this; anything larger is refused
  // whole instead of being cut mid-JSON (which always failed to parse)
  readonly property int reportMaxBytes: 1048576

  // Parses a report; returns null (and records why) when it is unusable
  function parseReport(raw) {
    var text = String(raw || "")
    if (text.length > root.reportMaxBytes) {
      root.markEngineError("Report too large (" + text.length + " bytes)")
      return null
    }
    try {
      var d = JSON.parse(text)
      if (!d || !d.modules || !d.threat_level) {
        root.markEngineError("Report is missing fields")
        return null
      }
      return d
    } catch(e) {
      root.markEngineError("Report is not valid JSON")
      return null
    }
  }

  function markEngineError(msg) {
    root.engineError = msg
    root.overallStatus = "ENGINE ERROR"
    root.threatLevel = "UNKNOWN"
  }

  function applyReport(d) {
    root.overallStatus = String(d.overall_status || "UNKNOWN")
    root.threatLevel = String(d.threat_level || "UNKNOWN")
    root.activeCount = Number(d.active_modules) || 0
    root.modules = root.withPendingToggles(d.modules || [])
    root.aiThreatScore = Number(d.ai_threat_score) || 0
    root.aiAnomalies = d.ai_anomalies || []
    root.kernelCapabilities = d.kernel_capabilities || []
    root.lastReportAt = Date.now()
    root.engineError = ""
  }

  // A report built before a toggle finished must not flip its switch back;
  // modules with a toggle in flight keep their optimistic state
  function withPendingToggles(mods) {
    var out = mods.slice()
    for (var i = 0; i < out.length; i++) {
      if (root.toggleSnapshots[out[i].id] !== undefined) {
        for (var j = 0; j < root.modules.length; j++) {
          if (root.modules[j].id === out[i].id) out[i] = root.modules[j]
        }
      }
    }
    return out
  }

  // "fresh" (applied), "stale" (valid but old or missing) or "invalid"
  function loadCachedReport(raw) {
    if (String(raw || "") === "") return "stale"
    var d = root.parseReport(raw)
    if (!d) return "invalid"
    var age = Date.now() / 1000 - Number(d.generated_at || 0)
    if (age < 0 || age > root.reportMaxAgeSec) return "stale"
    root.applyReport(d)
    return "fresh"
  }

  // A scan requested while one runs (e.g. right after an action) is queued,
  // otherwise the UI would keep showing the pre-action state.
  property bool rescanPending: false

  function scanNow() {
    if (stateProc.running) {
      root.rescanPending = true
      return
    }
    stateProc.running = true
  }

  function refresh() {
    // No report for too long: say so instead of showing the last (or no) verdict
    if (root.lastReportAt > 0 && Date.now() - root.lastReportAt > root.reportStaleSec * 1000) {
      root.markEngineError("No report for over " + root.reportStaleSec + " s")
    }
    if (root.reportCachePath === "") {
      root.scanNow()
      return
    }
    reportView.reload()
  }

  // The cache is missing or old: the daemon is not running (or died with the
  // dashboard that owned it). Start ours and scan once meanwhile.
  function cacheIsStale() {
    if (!daemonProc.running) daemonProc.running = true
    root.scanNow()
  }

  // pid:start_time pins the process the report showed; a PID reused since
  // the scan is refused by the engine instead of being frozen
  function kernelFreezeProcess(pid, startTime) {
    if (!pid) return
    var target = String(pid) + (Number(startTime) > 0 ? ":" + String(startTime) : "")
    root.runAction([root.resolveEnginePath(), "--kernel-freeze", target])
  }

  function toggleExpand(id) {
    expandedId = (expandedId === id ? "" : id)
  }

  // Switches flip immediately; if the engine exits non-zero (nmcli/omarchy-dns
  // failure, no Wi-Fi) the previous module state is restored at once instead of
  // showing a state the system is not in until the next scan.
  property var toggleSnapshots: ({})

  function optimisticToggle(modId, onSummary, offSummary, proc) {
    if (proc.running) return
    root.actionError = ""
    var mods = root.modules.slice()
    for (var i = 0; i < mods.length; i++) {
      if (mods[i].id === modId) {
        var snaps = root.toggleSnapshots
        snaps[modId] = mods[i]
        root.toggleSnapshots = snaps
        var m = Object.assign({}, mods[i])
        m.toggle_state = !m.toggle_state
        m.status = m.toggle_state ? "SECURE" : "WARNING"
        m.summary = m.toggle_state ? onSummary : offSummary
        mods[i] = m
        break
      }
    }
    root.modules = mods
    proc.running = true
  }

  function finishToggle(modId, code) {
    var snaps = root.toggleSnapshots
    var prev = snaps[modId]
    delete snaps[modId]
    root.toggleSnapshots = snaps
    if (code !== 0) root.actionError = "Toggle failed; the previous state was restored"
    if (code !== 0 && prev) {
      var mods = root.modules.slice()
      for (var i = 0; i < mods.length; i++) {
        if (mods[i].id === modId) {
          mods[i] = prev
          break
        }
      }
      root.modules = mods
    }
    root.scanNow()
  }

  function toggleGhostMac() {
    root.optimisticToggle("ghost_mac", "Randomized (Assigning...)", "Hardware MAC", toggleGhostProc)
  }

  function toggleDns() {
    root.optimisticToggle("dns", "DoT Active (Cloudflare)", "Unencrypted ISP DNS (DHCP)", toggleDnsProc)
  }

  function toggleUsbArmor() {
    root.optimisticToggle("badusb", "Armor Active", "Armor Disabled", toggleUsbArmorProc)
  }

  // Destructive actions need a second click within a few seconds
  property string armedAction: ""

  function confirmOrArm(key, action) {
    if (root.armedAction === key) {
      root.armedAction = ""
      disarmTimer.stop()
      action()
    } else {
      root.armedAction = key
      disarmTimer.restart()
    }
  }

  Timer {
    id: disarmTimer
    interval: 4000
    onTriggered: root.armedAction = ""
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
    root.runAction([root.resolveEnginePath(), "--scrub-downloads"])
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
        // Entries are already plain filesystem paths (decoded by the drop handler or
        // printed by zenity). Decoding again would corrupt names containing "%" and
        // throw URIError on names like "100%.png", aborting the whole batch.
        var f = String(fileList[i] || "")
        if (f.length > 0) {
          cmd.push(f)
        }
      }
      if (cmd.length > 2) {
        root.runAction(cmd)
      }
    }
  }

  function moduleIcon(id) {
    switch (id) {
      case "ai_behavior": return "󰚩"
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
    function refresh() { root.scanNow() }
    function toggleGhostMac() { root.toggleGhostMac() }
    function toggleDns() { root.toggleDns() }
    function expand(id: string) { root.toggleExpand(id) }
  }

  Process {
    id: pickFileProc
    command: ["zenity", "--file-selection", "--multiple", "--separator=\n", "--file-filter=Images | *.jpg *.jpeg *.png *.JPG *.JPEG *.PNG", "--title=OpSec: Select Images to Scrub EXIF"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var raw = String(text || "").trim()
        if (raw.length > 0) {
          // Newline separator: "|" is a legal character in file names
          var files = raw.split("\n")
          root.cleanFiles(files)
        }
      }
    }
  }

  Process {
    id: stateProc
    command: [root.resolveEnginePath(), "--json"]
    onExited: function(code) {
      if (code !== 0) root.markEngineError("Engine exited with code " + code + " (is sentinel-engine built and installed?)")
      if (root.rescanPending) {
        root.rescanPending = false
        root.scanNow()
      }
    }
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var d = root.parseReport(text)
        if (d) root.applyReport(d)
      }
    }
  }



  // Single instance per session (flock); a second panel's copy exits at once.
  // It dies with the shell via PR_SET_PDEATHSIG.
  Process {
    id: daemonProc
    command: [root.resolveEnginePath(), "--daemon"]
  }

  FileView {
    id: reportView
    path: root.reportCachePath
    watchChanges: true
    printErrors: false
    // An invalid cache does not trigger a scan: our own --json run rewrites the
    // file, which would fire this again and loop on back-to-back full scans
    onLoaded: {
      if (root.loadCachedReport(text()) === "stale") root.cacheIsStale()
    }
    onLoadFailed: root.cacheIsStale()
    onFileChanged: reload()
  }

  Process {
    id: toggleGhostProc
    command: [root.resolveEnginePath(), "--toggle-ghost-mac"]
    onExited: function(code) {
      root.finishToggle("ghost_mac", code)
    }
  }

  Process {
    id: toggleDnsProc
    command: [root.resolveEnginePath(), "--toggle-dns"]
    onExited: function(code) {
      root.finishToggle("dns", code)
    }
  }
  Process {
    id: toggleUsbArmorProc
    command: [root.resolveEnginePath(), "--toggle-usb-armor"]
    onExited: function(code) {
      root.finishToggle("badusb", code)
    }
  }


  Process {
    id: trustUsbProc
    command: [root.resolveEnginePath(), "--trust-all-usb"]
    onExited: function(code) {
      root.actionError = code !== 0 ? "Trust Devices failed: the USB baseline could not be saved" : ""
      root.scanNow()
    }
  }

  Process {
    id: resetCanariesProc
    command: [root.resolveEnginePath(), "--reset-canaries"]
    onExited: function(code) {
      root.scanNow()
    }
  }

  Process {
    id: actionProc
    // Kernel actions print an InterventionResult and exit 1 when it failed
    // (cancelled prompt, immune process, PID reused); show its message
    property string output: ""
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: actionProc.output = String(text || "")
    }
    onStarted: {
      actionProc.output = ""
      root.actionError = ""
    }
    onExited: function(code) {
      if (code !== 0) {
        var msg = "Action failed"
        try {
          var r = JSON.parse(actionProc.output.slice(0, 16384))
          if (r && r.message) msg = String(r.message)
        } catch(e) {}
        root.actionError = msg
      }
      root.scanNow()
      root.startNextAction()
    }
  }

  Timer {
    interval: 20000
    running: true
    repeat: true
    triggeredOnStart: true
    onTriggered: root.refresh()
  }

  Component.onDestruction: {
    if (stateProc.running) stateProc.running = false
    if (daemonProc.running) daemonProc.running = false
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
    foreground: {
      if (root.threatLevel === "CRITICAL" || root.engineDown) {
        return root.urgent
      } else {
        return root.bar ? root.bar.foreground : root.foreground
      }
    }
    tooltipText: "Security Sentinel Hub\nStatus: " + root.overallStatus + "\nThreat Level: " + root.threatLevel
      + (root.engineError !== "" ? "\n" + root.engineError : "")
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
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(500))
    contentHeight: panel.fittedContentHeight(panelColumn.implicitHeight)

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onCloseRequested: {
        if (root.showAboutModal) {
          root.showAboutModal = false
        } else {
          root.close()
        }
      }
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onMoveRequested: function(dx, dy) { root.moveCursor(dy) }
      onActivateRequested: root.activateSelected()
      onTextKey: function(t) {
        if (t === "r" || t === "R") {
          root.scanNow()
        } else if (t === "a" || t === "A") {
          root.showAboutModal = !root.showAboutModal
        }
      }

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
              if (urlStr.indexOf("file://") !== 0) continue
              try {
                files.push(decodeURIComponent(urlStr.replace(/^file:\/\//, "")))
              } catch (e) {
                console.warn("Security Sentinel: skipping undecodable drop URL", urlStr)
              }
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
          color: (root.threatLevel === "CRITICAL" || root.engineDown) ? root.urgent : root.foreground
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
          anchors.rightMargin: Style.space(8)
          anchors.verticalCenter: parent.verticalCenter
          spacing: Style.space(2)

          RowLayout {
            width: parent.width
            spacing: Style.space(8)

            Text {
              textFormat: Text.PlainText
              text: "Security Sentinel"
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.title
              font.bold: true
              Layout.fillWidth: true
              elide: Text.ElideRight
            }

            Button {
              iconText: "󰋽"
              tooltipText: "About & Imprint"
              foreground: root.foreground
              accent: root.accent
              fontFamily: root.fontFamily
              fontSize: Style.font.caption
              bordered: true
              onClicked: root.showAboutModal = !root.showAboutModal
            }
          }

          Text {
            textFormat: Text.PlainText
            text: root.overallStatus.toUpperCase()
            color: (root.threatLevel === "CRITICAL" || root.engineDown) ? root.urgent : root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            font.bold: true
            font.letterSpacing: 1.2
          }

          Text {
            textFormat: Text.PlainText
            text: "threat " + root.threatLevel.toLowerCase() + " · " + root.activeCount + " modules"
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption - 1
          }

          Text {
            visible: root.engineError !== "" || root.actionError !== ""
            width: parent.width
            textFormat: Text.PlainText
            text: root.actionError !== "" ? root.actionError : root.engineError
            color: root.urgent
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption - 1
            wrapMode: Text.WordWrap
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
        border.width: 1

        RowLayout {
          anchors.centerIn: parent
          spacing: Style.space(8)

          Text {
            textFormat: Text.PlainText
            text: "  Drop images here to strip EXIF & metadata"
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
              readonly property bool isToggleable: modData ? Boolean(modData.is_toggleable) : false
              readonly property bool isAlert: modStatus === "ALERT"
              readonly property bool isWarning: modStatus === "WARNING"
              readonly property bool isExpanded: root.expandedId === modId

              readonly property bool isKeyboardFocused: root.cursorActive && (index === root.selectedIndex)

              // Flat list: only the focused or open row gets a frame; alerts are
              // carried by the urgent colour of the icon, summary and status text.
              color: (isExpanded || isKeyboardFocused) ? Style.selectedFillFor(root.foreground, root.accent) : "transparent"
              border.color: (isExpanded || isKeyboardFocused) ? root.accent : "transparent"
              border.width: 1

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

                  // Background click area for left portion (title/icon)
                  MouseArea {
                    anchors.left: parent.left
                    anchors.top: parent.top
                    anchors.bottom: parent.bottom
                    width: Math.max(0, parent.width - (rowDelegate.isToggleable ? Style.space(110) : Style.space(50)))
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.toggleExpand(rowDelegate.modId)
                  }

                  RowLayout {
                    id: headerRow
                    anchors.fill: parent
                    spacing: Style.space(10)

                    // Module Icon
                    Text {
                      textFormat: Text.PlainText
                      text: root.moduleIcon(rowDelegate.modId)
                      color: rowDelegate.isAlert ? root.urgent : root.foreground
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
                        color: rowDelegate.isAlert ? root.urgent : root.dim
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        elide: Text.ElideRight
                      }
                    }

                    // Interactive Control / Status Indicator
                    Loader {
                      id: headerLoader
                      Layout.alignment: Qt.AlignVCenter
                      // Actions live in the expanded row and Quick Actions; the
                      // header only shows the switch or the verdict.
                      sourceComponent: rowDelegate.isToggleable ? toggleComp : badgeComp
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
                        text: "·"
                        color: root.dim
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
                    visible: rowDelegate.modId === "badusb" || rowDelegate.modId === "tripwire" || (rowDelegate.modId === "ai_behavior" && root.aiAnomalies.length > 0)
                    width: parent.width
                    height: (visible ? Style.space(32) : 0)

                    RowLayout {
                      anchors.fill: parent
                      spacing: Style.space(8)

                      Button {
                        visible: rowDelegate.modId === "ai_behavior" && root.aiAnomalies.length > 0
                        readonly property var freezeTarget: root.aiAnomalies.length > 0 ? root.aiAnomalies[0] : null
                        readonly property bool freezeArmed: freezeTarget !== null && root.armedAction === "freeze:" + freezeTarget.pid
                        text: !freezeTarget ? "" : (freezeArmed
                          ? "Confirm: freeze " + String(freezeTarget.name || "process") + " (PID " + freezeTarget.pid + ")"
                          : "Freeze PID " + freezeTarget.pid)
                        iconText: "󰟀"
                        foreground: freezeArmed ? root.urgent : root.foreground
                        accent: freezeArmed ? root.urgent : root.accent
                        fontFamily: root.fontFamily
                        fontSize: Style.font.caption
                        bordered: true
                        onClicked: {
                          if (!freezeTarget) return
                          var pid = freezeTarget.pid
                          var start = freezeTarget.start_time
                          root.confirmOrArm("freeze:" + pid, function() { root.kernelFreezeProcess(pid, start) })
                        }
                      }

                      Button {
                        visible: rowDelegate.modId === "badusb"
                        text: "Trust connected"
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
                        text: "Reset canaries"
                        iconText: ""
                        foreground: root.foreground
                        accent: root.accent
                        fontFamily: root.fontFamily
                        fontSize: Style.font.caption
                        bordered: true
                        onClicked: root.resetCanaries()
                      }
                    }
                  }
                }
              }

              Component {
                id: toggleComp
                ToggleSwitch {
                  checked: rowDelegate.modData ? Boolean(rowDelegate.modData.toggle_state) : false
                  busy: (rowDelegate.modId === "ghost_mac" && toggleGhostProc.running)
                    || (rowDelegate.modId === "dns" && toggleDnsProc.running)
                    || (rowDelegate.modId === "badusb" && toggleUsbArmorProc.running)
                  foreground: root.foreground
                  accent: root.accent
                  onToggled: {
                    if (rowDelegate.modId === "ghost_mac") {
                      root.toggleGhostMac()
                    } else if (rowDelegate.modId === "badusb") {
                      root.toggleUsbArmor()
                    } else if (rowDelegate.modId === "dns") {
                      root.toggleDns()
                    }
                  }
                }
              }

              Component {
                id: badgeComp
                Text {
                  textFormat: Text.PlainText
                  text: rowDelegate.modStatus.toLowerCase()
                  color: (rowDelegate.isAlert || rowDelegate.isWarning) ? root.urgent : root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: rowDelegate.isAlert
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
            onClicked: root.scanNow()
          }
        }
      }
    }

    // About & Imprint Modal Overlay
    Rectangle {
      id: aboutOverlay
      anchors.fill: parent
      visible: root.showAboutModal
      color: Qt.rgba(0, 0, 0, 0.6)
      z: 99

      MouseArea {
        anchors.fill: parent
        // Block underlying clicks; clicking the dimmed area closes the dialog
        onClicked: root.showAboutModal = false
      }

      // Opaque card: the overlay alone let the module list show through and the
      // header row overflowed it on narrow panels.
      Rectangle {
        id: aboutCard
        anchors.centerIn: parent
        width: parent.width - Style.space(32)
        height: aboutColumn.implicitHeight + Style.space(32)
        color: Color.popups.background
        border.color: root.dim
        border.width: 1

        MouseArea {
          anchors.fill: parent
          // Swallow clicks so only the dimmed area outside the card closes it
        }

      Column {
        id: aboutColumn
        anchors.centerIn: parent
        width: parent.width - Style.space(32)
        spacing: Style.space(12)

        RowLayout {
          width: parent.width
          spacing: Style.space(8)

          Text {
            id: aboutTitleText
            Layout.fillWidth: true
            text: root.pluginName
            textFormat: Text.PlainText
            color: root.foreground
            font.family: root.fontFamily
            font.pixelSize: Style.font.title
            font.bold: true
            elide: Text.ElideRight
          }

          Button {
            id: closeAboutBtn
            Layout.alignment: Qt.AlignVCenter
            text: "✕"
            bordered: true
            foreground: root.foreground
            fontFamily: root.fontFamily
            fontSize: Style.font.caption
            onClicked: root.showAboutModal = false
          }
        }

        Text {
          textFormat: Text.PlainText
          text: "Sürüm: " + root.pluginVersion + "\nGeliştirici: " + root.pluginAuthor + "\nLisans: " + root.pluginLicense + "\n\n" + root.pluginDescription
          color: root.foreground
          opacity: 0.8
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          lineHeight: 1.3
          wrapMode: Text.WordWrap
          width: parent.width
        }

        PanelSeparator {
          width: parent.width
          foreground: root.foreground
        }

        Button {
          width: parent.width
          text: "GitHub / Contact"
          iconText: "󰊤"
          bordered: true
          foreground: root.foreground
          accent: root.accent
          fontFamily: root.fontFamily
          fontSize: Style.font.caption
          onClicked: Qt.openUrlExternally("https://github.com/ozdil")
        }

        Button {
          width: parent.width
          text: "Buy Me a Coffee"
          iconText: "󰅶"
          bordered: true
          foreground: root.foreground
          accent: root.accent
          fontFamily: root.fontFamily
          fontSize: Style.font.caption
          onClicked: Qt.openUrlExternally("https://buymeacoffee.com/ozdil")
        }
      }
      }
    }
    }
  }
}
