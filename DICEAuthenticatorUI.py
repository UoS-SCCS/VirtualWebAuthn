from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *

import sys
from abc import ABC, abstractmethod
import threading
class DICEAuthenticatorListener:
    @abstractmethod
    def shutdown(self):
        pass
    @abstractmethod
    def menu_clicked(self, menu_item):
        pass

class DICEAuthenticatorUI:
    def __init__(self):
        self._listeners = []
        pass

    @abstractmethod
    def start(self):
        pass

    @abstractmethod
    def add_listener(self, listener:DICEAuthenticatorListener):
        self._listeners.append(listener)

    @abstractmethod
    def check_user_presence(self, msg=None):
        pass
    
    def fire_event_shutdown(self):
        for listener in self._listeners:
            listener.shutdown()

class ConsoleAuthenticatorUI(DICEAuthenticatorUI):
    def __init__(self):
        super().__init__()
        self.type="Console"

    def start(self):
        while 1:
            for line in sys.stdin:
                if line.rstrip() == "quit":
                    #This doesn't actually kill the thread because python handles threads in a bizarre way
                    self.fire_event_shutdown()
                    sys.exit()
        else:
            print("Unknown command entered on CLI: %s" % line.rstrip() )

    def check_user_presence(self, msg=None):
        pass

class LabelWidget(QWidgetAction):
    def __init__(self, parent:QObject):
        super().__init__(parent)

    def createWidget(self, parent:QWidget)->QWidget:
        return QLabel("Hello world")

class QTAuthenticatorUI:
    def __init__(self):
        self.app=None
        self._listeners = []
        pass


    def start(self):
        self.app = QApplication([])
        self.app.setQuitOnLastWindowClosed(False)
        
        # Create the icon
        icon = QIcon("./ui/die.png")

        # Create the tray
        self.tray = QSystemTrayIcon()
        self.tray.setIcon(icon)
        self.tray.setVisible(True)

        
        
        # Create the menu
        menu = QMenu()
        self.object = QObject()
        wa = QWidgetAction(menu)
        wa.setDefaultWidget(QCheckBox("Hello"))
        menu.addAction(wa)

        action = QAction("A menu item")
        menu.addAction(action)

        # Add a Quit option to the menu.
        quit = QAction("Quit")
        quit.triggered.connect(self._quit)
        menu.addAction(quit)

        # Add the menu to the tray
        self.tray.setContextMenu(menu)
        
        #self.dialog.show()
        #for some reason this has to be called from the same function. Calling it later doesn't work
        self.app.exec_()
    
    def check_user_presence(self, msg=None):
        print("inhere")
        self.dialog = QDialog(flags = Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        
        layout = QVBoxLayout(self.dialog)
        layout.addWidget(QLabel("DICE Key Notification"))
        label = QLabel("Website X wishes to access your DICEKey")
        label.setWordWrap(True)
        layout.addWidget(label)
        frame = QFrame()
        blayout = QHBoxLayout(frame)
        blayout.addWidget(QPushButton("Allow"))
        blayout.addWidget(QPushButton("Deny"))
        frame.setLayout(blayout)
        layout.addWidget(frame)
        
        self.dialog.setLayout(layout)
        geo = self.tray.geometry()
        
        #self.dialog.setGeometry(geo.left,geo.bottom)
        self.dialog.show()
        self.dialog.exec_()
    def _quit(self):
        for listener in self._listeners:
            listener.shutdown()
        self.app.quit()
    def add_listener(self, listener:DICEAuthenticatorListener):
        self._listeners.append(listener)