import QtQuick
import Quickshell
import Quickshell.Io
import "theme"

ShellRoot {
    id: root

    FloatingWindow {
        id: win
        title: "Security Sentinel - Zero-Trust Security Center & Threat Shield"
        implicitWidth: 1140
        implicitHeight: 740
        color: Theme.bgBase

        MainWindow {
            id: mainWin
            anchors.fill: parent
        }
    }

    IpcHandler {
        target: "ozdil.sentinel"

        function toggle(): bool {
            win.visible = !win.visible;
            return win.visible;
        }

        function show(): bool {
            win.visible = true;
            return true;
        }

        function hide(): bool {
            win.visible = false;
            return false;
        }

        function refresh(): string {
            mainWin.refresh();
            return "OK";
        }
    }
}
