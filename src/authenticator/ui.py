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
from enum import Enum, unique
import os
import time
import threading

from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (QWidgetAction,QLabel,QApplication,
    QSystemTrayIcon, QMenu, QVBoxLayout, QFrame, QHBoxLayout, QCheckBox,
    QAction, QDialog,QPushButton, QDesktopWidget, QGraphicsDropShadowEffect,
    QLineEdit)
from PyQt5.QtCore import QObject, Qt, QEvent, QTimer
result_available = threading.Event()
result = None
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

    def post_ui_load(self):
        """Fired when the UI has finished loading
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

    @abstractmethod
    def get_user_password(self, msg:str=None):
        """Requests a password from the user

        Args:
            msg (str, optional): The notification message to show
            if not just a default. Defaults to None.
        """

    @abstractmethod
    def check_user_verification(self, msg:str=None):
        """Performs a user verification test

        Args:
            msg (str, optional): The notification message to show
            if not just a default. Defaults to None.
        """
    @abstractmethod
    def create(self):
        """Creates the UI but doesn't show it yet
        """

    @abstractmethod
    def shutdown(self):
        """Requests the UI to initiate a shutdown, equivalent to exit in the UI
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

    def fire_post_ui_loaded(self):
        """Fires the menu clicked event

        Args:
            menu_item (str): menu item that was clicked
        """
        time.sleep(0.05)
        for listener in self._listeners:
            listener.post_ui_load()

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

    def get_user_password(self, msg:str=None):
        pass

    def check_user_verification(self, msg:str=None):
        pass

    def create(self):
        pass

    def shutdown(self):
        self.fire_event_shutdown()
        sys.exit(0)

@unique
class DICE_UI_Event(Enum):
    SHOW_UP = QEvent.Type(QEvent.registerEventType())
    SHOW_UV = QEvent.Type(QEvent.registerEventType())
    SHOW_PWD = QEvent.Type(QEvent.registerEventType())
class DICEEvent(QEvent):
    def __init__(self,action:DICE_UI_Event):
        QEvent.__init__(self, action.value)
        self.dice_type = action
        self.msg = ""
    def set_message(self, msg:str):
        self.msg = msg

class QTAuthenticatorUIApp(QApplication):
    def __init__(self):
        super().__init__([])
        self.pwd_box = None
        self.dialog = None
        self.pwd_box_uv = None
    def customEvent(self, event):
        if event.dice_type == DICE_UI_Event.SHOW_UP:
            self.show_user_presence(event.msg)
        if event.dice_type == DICE_UI_Event.SHOW_PWD:
            self.get_user_password(event.msg)
        if event.dice_type == DICE_UI_Event.SHOW_UV:
            self.get_user_verification(event.msg)


    def show_user_presence(self, msg:str="User Presence Check"):
        self.dialog = QDialog(flags = Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
        self.dialog.setAttribute(Qt.WA_TranslucentBackground)
        parent_path = os.path.dirname(os.path.abspath(__file__))
        outer_layout = QVBoxLayout(self.dialog)
        outer_layout.setContentsMargins(0,0,0,0)
        outer_frame = QFrame()

        outer_frame.setProperty("bgFrame",True)
        outer_frame.setStyleSheet("#header {font-weight:bold; text-align:center;}\n*[bgFrame='true'] {border-image: url(" + parent_path +"/icons/bgpy.png" +") 0 0 0 0 stretch stretch;}")


        #background-image: url(" + parent_path +"/icons/bgpy.png" +"); background-repeat: no-repeat; background-size: auto;background-attachment: fixed}
        #effect = QGraphicsDropShadowEffect()
        #effect.setBlurRadius(5);
        #self.dialog.setGraphicsEffect(effect);
        outer_layout.addWidget(outer_frame)
        layout = QVBoxLayout(outer_frame)
        header = QLabel("DICE Key Notification");
        header.setObjectName("header")
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)
        label = QLabel(msg)
        label.setWordWrap(True)
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)
        frame = QFrame()
        blayout = QHBoxLayout(frame)
        allow_button = QPushButton("Allow")
        deny_button = QPushButton("Deny")
        allow_button.clicked.connect(lambda:self._perm_button_clicked(True))
        deny_button.clicked.connect(lambda:self._perm_button_clicked(False))
        blayout.addWidget(allow_button)
        blayout.addWidget(deny_button)
        frame.setLayout(blayout)
        layout.addWidget(frame)
        outer_frame.setLayout(layout)
        self.dialog.setLayout(outer_layout)


        screen_shape = QDesktopWidget().screenGeometry()
        self.dialog.setGeometry(screen_shape.width()-440,0,350,200)
        self.dialog.show()

    def get_user_password(self, msg:str="Enter Password"):
        self.dialog = QDialog(flags = Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
        self.dialog.setAttribute(Qt.WA_TranslucentBackground)
        parent_path = os.path.dirname(os.path.abspath(__file__))
        outer_layout = QVBoxLayout(self.dialog)
        outer_layout.setContentsMargins(0,0,0,0)
        outer_frame = QFrame()

        outer_frame.setProperty("bgFrame",True)
        outer_frame.setStyleSheet("#header {font-weight:bold; text-align:center;}\n*[bgFrame='true'] {border-image: url(" + parent_path +"/icons/bgpy.png" +") 0 0 0 0 stretch stretch;}")
        outer_layout.addWidget(outer_frame)
        layout = QVBoxLayout(outer_frame)
        header = QLabel("DICE Key Notification");
        header.setObjectName("header")
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)
        label = QLabel(msg)
        label.setWordWrap(True)
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)
        frame = QFrame()
        blayout = QHBoxLayout(frame)
        self.pwd_box = QLineEdit()
        self.pwd_box.setEchoMode(QLineEdit.Password)
        blayout.addWidget(self.pwd_box)
        submit_button = QPushButton("Submit")
        submit_button.clicked.connect(self._submit_pwd_button_clicked)
        blayout.addWidget(submit_button)
        frame.setLayout(blayout)
        layout.addWidget(frame)
        outer_frame.setLayout(layout)
        self.dialog.setLayout(outer_layout)


        screen_shape = QDesktopWidget().screenGeometry()

        self.pwd_box.setFocus()
        self.dialog.setGeometry(screen_shape.width()-440,0,350,200)
        self.dialog.show()

    def get_user_verification(self, msg:str="Enter Password"):
        self.dialog = QDialog(flags = Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
        self.dialog.setAttribute(Qt.WA_TranslucentBackground)
        parent_path = os.path.dirname(os.path.abspath(__file__))
        outer_layout = QVBoxLayout(self.dialog)
        outer_layout.setContentsMargins(0,0,0,0)
        outer_frame = QFrame()

        outer_frame.setProperty("bgFrame",True)
        outer_frame.setStyleSheet("#header {font-weight:bold; text-align:center;}\n*[bgFrame='true'] {border-image: url(" + parent_path +"/icons/bgpy.png" +") 0 0 0 0 stretch stretch;}")
        outer_layout.addWidget(outer_frame)
        layout = QVBoxLayout(outer_frame)
        header = QLabel("DICE Key Notification");
        header.setObjectName("header")
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)
        label = QLabel(msg)
        label.setWordWrap(True)
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)
        frame = QFrame()
        blayout = QHBoxLayout(frame)
        self.pwd_box_uv = QLineEdit()
        self.pwd_box_uv.setEchoMode(QLineEdit.Password)
        blayout.addWidget(self.pwd_box_uv)
        frame.setLayout(blayout)
        layout.addWidget(frame)

        framebtn = QFrame()
        btnlayout = QHBoxLayout(framebtn)
        allow_button = QPushButton("Allow")
        deny_button = QPushButton("Deny")
        allow_button.clicked.connect(lambda:self._uv_button_clicked(True))
        deny_button.clicked.connect(lambda:self._uv_button_clicked(False))
        btnlayout.addWidget(allow_button)
        btnlayout.addWidget(deny_button)
        framebtn.setLayout(btnlayout)
        layout.addWidget(framebtn)

        outer_frame.setLayout(layout)
        self.dialog.setLayout(outer_layout)


        screen_shape = QDesktopWidget().screenGeometry()
        self.dialog.setGeometry(screen_shape.width()-440,0,350,200)
        self.pwd_box_uv.setFocus()
        self.dialog.show()

    def _perm_button_clicked(self, outcome:bool):
        #self.user_presence_allow = outcome
        self.dialog.close()
        global result
        result = outcome
        result_available.set()

    def _submit_pwd_button_clicked(self):
        global result
        result = self.pwd_box.text()
        self.dialog.close()
        result_available.set()


    def _uv_button_clicked(self, approved:bool):
        global result
        if approved:
            result = self.pwd_box_uv.text()
        else:
            result = False
        self.dialog.close()
        result_available.set()

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
        self.user_presence_allow = False



    def create(self):
        self.app = QTAuthenticatorUIApp()
        self.app.setQuitOnLastWindowClosed(False)






    def start(self):
        #QTimer.singleShot(50, self.fire_post_ui_loaded)
        thread = threading.Thread(target=self.fire_post_ui_loaded)
        thread.setDaemon(True)
        thread.start()
        parent_path = os.path.dirname(os.path.abspath(__file__))
        # Create the icon
        icon = QIcon(parent_path + "/icons/die.png")

        # Create the tray
        self.tray = QSystemTrayIcon()
        self.tray.setIcon(icon)
        self.tray.setVisible(True)

        # Create the menu
        menu = QMenu()
        prefs = QAction("Preferences")
        prefs.triggered.connect(self._preferences)
        menu.addAction(prefs)

        user = QAction("Dummy User Presence")
        user.triggered.connect(self._test_method)
        menu.addAction(user)

        #self.object = QObject()
        #widget_action = QWidgetAction(menu)
        #widget_action.setDefaultWidget(QCheckBox("Hello"))
        #menu.addAction(widget_action)

        action = QAction("A menu item")
        menu.addAction(action)

        # Add a Quit option to the menu.
        quit_app = QAction("Quit")
        quit_app.triggered.connect(self._quit)
        menu.addAction(quit_app)
        self.menu = menu
        # Add the menu to the tray
        self.tray.setContextMenu(menu)
        self.app.exec_()

    def _test_method(self):
        print(self.check_user_presence("Relying Party: wishes to use your DICE Key"))

    def _preferences(self):
        pass

    def _reset_lock(self):
        result_available.clear()
        global result
        result = None

    def check_user_presence(self, msg:str="User Presence Check")->bool:
        dice_event = DICEEvent(DICE_UI_Event.SHOW_UP)
        dice_event.set_message(msg)
        self._reset_lock()
        QApplication.postEvent(self.app,dice_event)
        result_available.wait()
        return result

    def get_user_password(self, msg:str=None)->str:
        dice_event = DICEEvent(DICE_UI_Event.SHOW_PWD)
        dice_event.set_message(msg)
        self._reset_lock()
        #QApplication.sendEvent(self.app,dice_event)
        QApplication.postEvent(self.app,dice_event)
        result_available.wait()
        return result

    def check_user_verification(self, msg:str=None):
        dice_event = DICEEvent(DICE_UI_Event.SHOW_UV)
        dice_event.set_message(msg)
        self._reset_lock()
        #QApplication.sendEvent(self.app,dice_event)
        QApplication.postEvent(self.app,dice_event)
        result_available.wait()
        return result

    def shutdown(self):
        self._quit()
    def _quit(self):
        for listener in self._listeners:
            listener.shutdown()
        self.app.quit()
