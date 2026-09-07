import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
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

  function resolveEnginePath() {
    return Qt.resolvedUrl("sentinel-engine").toString().replace(/^file:\/\//, "")
  }

  function refresh() {
    if (!stateProc.running) {
      stateProc.running = true
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
        var f = String(fileList[i] || "").trim()
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

  IpcHandler {
    target: "ozdil.security-sentinel"
    function open() { root.open() }
    function close() { root.close() }
    function toggle() { root.toggle() }
    function refresh() { root.refresh() }
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
    id: actionProc
    onExited: function(code) {
      root.refresh()
    }
  }

  Timer {
    interval: 30000
    running: true
    repeat: true
    triggeredOnStart: true
    onTriggered: root.refresh()
  }

  Component.onCompleted: refresh()
  Component.onDestruction: {
    if (stateProc.running) stateProc.running = false
    if (actionProc.running) actionProc.running = false
    if (pickFileProc.running) pickFileProc.running = false
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: ""
    tooltipText: "Security Sentinel Hub"
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
    contentWidth: panel.fittedContentWidth(Style.space(420))
    contentHeight: panel.fittedContentHeight(panelColumn.implicitHeight, Style.space(560))

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

    ScrollView {
      id: scrollArea
      anchors.fill: parent
      clip: true
      ScrollBar.horizontal.policy: ScrollBar.AlwaysOff
      ScrollBar.vertical.policy: panelColumn.implicitHeight > height ? ScrollBar.AsNeeded : ScrollBar.AlwaysOff

      Column {
        id: panelColumn
        width: scrollArea.availableWidth
        spacing: Style.space(14)

        // ---------- Hero: Shield icon · title/status ----------
        Item {
          width: parent.width
          implicitHeight: Math.max(heroIcon.implicitHeight, heroLabels.implicitHeight)

          Text {
            id: heroIcon
            textFormat: Text.PlainText
            text: ""
            color: root.bar ? root.bar.foreground : Color.foreground
            font.family: root.bar ? root.bar.fontFamily : Style.font.family
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
              color: root.bar ? root.bar.foreground : Color.foreground
              font.family: root.bar ? root.bar.fontFamily : Style.font.family
              font.pixelSize: Style.font.title
              font.bold: true
              elide: Text.ElideRight
              width: parent.width
            }

            Text {
              textFormat: Text.PlainText
              text: root.overallStatus.toUpperCase()
              color: root.threatLevel === "ZERO" ? Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.4) : Color.urgent
              font.family: root.bar ? root.bar.fontFamily : Style.font.family
              font.pixelSize: Style.font.caption
              font.bold: true
              font.letterSpacing: 1.2
            }
          }
        }

        // ---------- Drop Banner ----------
        Rectangle {
          visible: dropArea.containsDrag
          width: parent.width
          height: Style.space(38)
          radius: Style.space(4)
          color: Style.selectedFillFor(root.bar ? root.bar.foreground : Color.foreground, Color.accent)
          border.color: Color.accent
          border.width: 1

          RowLayout {
            anchors.centerIn: parent
            spacing: Style.space(8)

            Text {
              textFormat: Text.PlainText
              text: "📥 Drop images here to strip EXIF & metadata"
              color: Color.accent
              font.family: root.bar ? root.bar.fontFamily : Style.font.family
              font.pixelSize: Style.font.bodySmall
              font.bold: true
            }
          }
        }

        // ---------- Subsystems Section ----------
        PanelSeparator {
          foreground: root.bar ? root.bar.foreground : Color.foreground
        }

        Column {
          width: parent.width
          spacing: Style.space(6)

          PanelSectionHeader {
            text: "SUBSYSTEMS"
            foreground: root.bar ? root.bar.foreground : Color.foreground
            fontFamily: root.bar ? root.bar.fontFamily : Style.font.family
          }

          Column {
            width: parent.width
            spacing: Style.space(4)

            Repeater {
              model: root.modules
              delegate: Rectangle {
                id: rowDelegate
                width: parent.width
                height: Style.space(34)
                radius: Style.space(4)

                readonly property var modData: modelData
                readonly property bool isOpSec: modData && modData.name === "OpSec Metadata Scrubber"
                readonly property bool isHovered: isOpSec && opSecMouse.containsMouse

                color: isHovered
                       ? Qt.darker(Color.accent, 2.8)
                       : Style.selectedFillFor(root.bar ? root.bar.foreground : Color.foreground, Color.accent)
                border.color: isHovered ? Color.accent : "transparent"
                border.width: isHovered ? 1 : 0

                RowLayout {
                  anchors.fill: parent
                  anchors.leftMargin: Style.space(10)
                  anchors.rightMargin: Style.space(10)
                  spacing: Style.space(8)

                  Text {
                    Layout.fillWidth: true
                    textFormat: Text.PlainText
                    text: modData ? String(modData.name) : "--"
                    color: isHovered ? Color.accent : (root.bar ? root.bar.foreground : Color.foreground)
                    font.family: root.bar ? root.bar.fontFamily : Style.font.family
                    font.pixelSize: Style.font.bodySmall
                    font.bold: isHovered
                    elide: Text.ElideRight
                  }

                  Text {
                    textFormat: Text.PlainText
                    text: isHovered ? "Click to pick file " : (modData ? String(modData.summary) : "--")
                    color: isHovered ? Color.accent : Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.4)
                    font.family: root.bar ? root.bar.fontFamily : Style.font.family
                    font.pixelSize: Style.font.caption
                    horizontalAlignment: Text.AlignRight
                    elide: Text.ElideRight
                  }
                }

                MouseArea {
                  id: opSecMouse
                  anchors.fill: parent
                  hoverEnabled: true
                  enabled: rowDelegate.isOpSec
                  cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
                  onClicked: root.openFilePicker()
                }
              }
            }
          }
        }

        // ---------- Actions Section ----------
        PanelSeparator {
          foreground: root.bar ? root.bar.foreground : Color.foreground
        }

        Column {
          width: parent.width
          spacing: Style.space(6)

          PanelSectionHeader {
            text: "ACTIONS"
            foreground: root.bar ? root.bar.foreground : Color.foreground
            fontFamily: root.bar ? root.bar.fontFamily : Style.font.family
          }

          RowLayout {
            width: parent.width
            spacing: Style.space(8)

            Button {
              Layout.fillWidth: true
              text: "Scrub File..."
              onClicked: root.openFilePicker()
            }

            Button {
              Layout.fillWidth: true
              text: "Scrub Downloads"
              onClicked: root.scrubDownloads()
            }

            Button {
              Layout.fillWidth: true
              text: "Audit Now"
              onClicked: root.refresh()
            }
          }
        }
      }
    }
  }
}
