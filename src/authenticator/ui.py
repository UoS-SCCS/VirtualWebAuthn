"""Provides abstract and concrete UI classes

An abstract UI is defined that can be provided by either a CLI
interface or a QT interface. Both examples are provided

Classes:
    DICEAuthenticatorListener
    DICEAuthenticatorUI
    ConsoleAuthenticatorUI
    QTAuthenticatorUI

"""
import sys
from abc import ABC, abstractmethod

from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (QWidgetAction,QLabel,QApplication,
    QSystemTrayIcon, QMenu, QVBoxLayout, QFrame, QHBoxLayout, QCheckBox,
    QAction, QDialog,QPushButton)
from PyQt5.QtCore import QObject, Qt

class DICEAuthenticatorListener(ABC):
    """Defines the listener interface for authenticators
    that wish to listen to UI events
    """
    @abstractmethod
    def shutdown(self):
        """Fired when the application should shutdown, could
        be triggered by entering a Quit command on the CLI or
        clicking a menu
        """

    @abstractmethod
    def menu_clicked(self, menu_item:str):
        """Fired when a menu selection is made with the menu item
        included

        Args:
            menu_item (str): menu item that was selected
        """

class DICEAuthenticatorUI(ABC):
    """Abstract UI class that should be implemented by a
    compatible UI

    """
    def __init__(self):
        self._listeners = []


    @abstractmethod
    def start(self):
        """Called to start the UI. This is necessary where the
        UI will run either in the main thread or a new thread
        """

    def add_listener(self, listener:DICEAuthenticatorListener):
        """Adds a listener to receive UI events

        Args:
            listener (DICEAuthenticatorListener): listener to be added
        """
        self._listeners.append(listener)

    @abstractmethod
    def check_user_presence(self, msg:str=None):
        """Performs a user presence check. How this is performed
        is left up to the UI, it could be pop-up, notifiaction
        or some other interface

        Args:
            msg (str, optional): The notification message to show
            if not just a default. Defaults to None.
        """

    def fire_event_shutdown(self):
        """Fires the shutdown event to all listeners
        """
        for listener in self._listeners:
            listener.shutdown()

    def fire_menu_clicked(self, menu_item:str):
        """Fires the menu clicked event

        Args:
            menu_item (str): menu item that was clicked
        """
        for listener in self._listeners:
            listener.menu_clicked(menu_item)

class ConsoleAuthenticatorUI(DICEAuthenticatorUI):
    """Simple console UI to allow the user to perform
    basic operations like quiting.

    """
    def __init__(self):
        super().__init__()
        self.type="Console"

    def start(self):
        while 1:
            for line in sys.stdin:
                if line.rstrip() == "quit":
                    #This doesn't actually kill the thread because
                    #python handles threads in a slightly odd way
                    self.fire_event_shutdown()
                    sys.exit()
                else:
                    print("Unknown command entered on CLI: %s" % line.rstrip() )

    def check_user_presence(self, msg:str=None):
        pass

class QTAuthenticatorUI(DICEAuthenticatorUI):
    """QT based UI that provides a system tray icon and more
    sophisticated user interaction functionality
    """
    def __init__(self):
        super().__init__()
        self.app=None
        self._listeners = []
        self.tray = None
        self.object = None
        self.dialog = None

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
        widget_action = QWidgetAction(menu)
        widget_action.setDefaultWidget(QCheckBox("Hello"))
        menu.addAction(widget_action)

        action = QAction("A menu item")
        menu.addAction(action)

        # Add a Quit option to the menu.
        quit_app = QAction("Quit")
        quit_app.triggered.connect(self._quit)
        menu.addAction(quit_app)

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
        #geo = self.tray.geometry()

        #self.dialog.setGeometry(geo.left,geo.bottom)
        self.dialog.show()
        self.dialog.exec_()
    def _quit(self):
        for listener in self._listeners:
            listener.shutdown()
        self.app.quit()
