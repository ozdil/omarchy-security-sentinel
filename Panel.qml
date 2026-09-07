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
  property string threatColor: "#22c55e"
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

  IpcHandler {
    target: "ozdil.security-sentinel"
    function open() { root.open() }
    function close() { root.close() }
    function toggle() { root.toggle() }
    function refresh() { root.refresh() }
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
          root.threatColor = String(d.threat_color || "#22c55e")
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
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: "\uf0483"
    foreground: root.threatColor
    slotSize: Style.bar.statusSlot
    tooltipText: "Security Sentinel Hub\nStatus: " + root.overallStatus + "\nThreat Level: " + root.threatLevel + "\nActive Subsystems: " + root.activeCount + " / 8\n\n[Left Click] Open Security Center"

    onPressed: function(b) {
      if (root.opened) root.close()
      else root.open()
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    contentWidth: panel.fittedContentWidth(Style.space(520))
    contentHeight: panel.fittedContentHeight(contentCol.implicitHeight)

    Column {
      id: contentCol
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.top: parent.top
      spacing: Style.space(12)

      // ---------- Header ----------
      Item {
        width: parent.width
        implicitHeight: Math.max(heroLabels.implicitHeight, heroActions.implicitHeight)

        Column {
          id: heroLabels
          anchors.left: parent.left
          anchors.right: heroActions.left
          anchors.rightMargin: Style.space(10)
          anchors.verticalCenter: parent.verticalCenter
          spacing: Style.space(2)

          RowLayout {
            spacing: Style.space(8)
            Text {
              textFormat: Text.PlainText
              text: "SECURITY SENTINEL"
              color: root.bar ? root.bar.foreground : Color.foreground
              font.family: root.bar ? root.bar.fontFamily : Style.font.family
              font.pixelSize: Style.font.title
              font.bold: true
            }

            Rectangle {
              height: Style.space(18)
              width: badgeText.implicitWidth + Style.space(12)
              radius: Style.space(4)
              color: Qt.alpha(root.threatColor, 0.15)
              border.color: root.threatColor
              border.width: 1

              Text {
                id: badgeText
                anchors.centerIn: parent
                textFormat: Text.PlainText
                text: root.threatLevel + " THREAT"
                color: root.threatColor
                font.family: root.bar ? root.bar.fontFamily : Style.font.family
                font.pixelSize: Style.font.caption
                font.bold: true
              }
            }
          }

          Text {
            textFormat: Text.PlainText
            text: "UNIFIED CYBER DEFENSE & PRIVACY HUB (" + root.activeCount + " SUBSYSTEMS)"
            color: Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.4)
            font.family: root.bar ? root.bar.fontFamily : Style.font.family
            font.pixelSize: Style.font.caption
            font.bold: true
            font.letterSpacing: 1.2
          }
        }

        RowLayout {
          id: heroActions
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          spacing: Style.space(6)

          Button {
            text: "Scrub Downloads"
            onClicked: root.scrubDownloads()
          }

          Button {
            text: "Audit Now"
            onClicked: root.refresh()
          }
        }
      }

      PanelSeparator {
        foreground: root.bar ? root.bar.foreground : Color.foreground
      }

      // ---------- Modules List ----------
      Column {
        width: parent.width
        spacing: Style.space(8)

        Repeater {
          model: root.modules
          delegate: Rectangle {
            width: parent.width
            height: Style.space(48)
            radius: Style.space(6)
            color: Qt.alpha(root.bar ? root.bar.foreground : Color.foreground, 0.04)
            border.color: Qt.alpha(root.bar ? root.bar.foreground : Color.foreground, 0.1)
            border.width: 1

            readonly property var modData: modelData

            RowLayout {
              anchors.fill: parent
              anchors.leftMargin: Style.space(12)
              anchors.rightMargin: Style.space(12)
              spacing: Style.space(10)

              Column {
                Layout.fillWidth: true
                spacing: Style.space(2)

                Text {
                  textFormat: Text.PlainText
                  text: modData ? String(modData.name) : "--"
                  color: root.bar ? root.bar.foreground : Color.foreground
                  font.family: root.bar ? root.bar.fontFamily : Style.font.family
                  font.pixelSize: Style.font.body
                  font.bold: true
                }

                Text {
                  textFormat: Text.PlainText
                  text: modData ? String(modData.detail) : "--"
                  color: Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.4)
                  font.family: root.bar ? root.bar.fontFamily : Style.font.family
                  font.pixelSize: Style.font.caption
                  elide: Text.ElideRight
                }
              }

              Column {
                Layout.preferredWidth: Style.space(160)
                spacing: Style.space(2)

                Text {
                  textFormat: Text.PlainText
                  width: parent.width
                  horizontalAlignment: Text.AlignRight
                  text: modData ? String(modData.status) : "--"
                  color: (modData && modData.status === "SECURE" || modData && modData.status === "READY") ? "#22c55e" : "#ef4444"
                  font.family: root.bar ? root.bar.fontFamily : Style.font.family
                  font.pixelSize: Style.font.bodySmall
                  font.bold: true
                }

                Text {
                  textFormat: Text.PlainText
                  width: parent.width
                  horizontalAlignment: Text.AlignRight
                  text: modData ? String(modData.summary) : "--"
                  color: Qt.darker(root.bar ? root.bar.foreground : Color.foreground, 1.3)
                  font.family: root.bar ? root.bar.fontFamily : Style.font.family
                  font.pixelSize: Style.font.caption
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
