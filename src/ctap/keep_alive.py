import threading
import time
from ctap.messages import CTAPHIDKeepAliveResponse
import ctap.constants

import logging
log = logging.getLogger('debug')

class CTAPHIDKeepAlive():
    def __init__(self, ctaphid):
        self._interval = (1/1000)*1000
        self._ctaphid = ctaphid
        self._cid = None
        self._status = ctap.constants.CTAPHID_KEEPALIVE_STATUS.STATUS_PROCESSING
        self._running = False
        self._keep_alive_thread = None
        self._elapsed =0
        self._max = 0
    
    def set_CID(self, CID:bytes):
        self._cid = CID

    def start(self, max_val=120000):
        if self._cid is None:
            raise Exception("Keep-alive channel not set")
        log.debug("Start keep-alive called")
        self._max = max_val/1000
        self._keep_alive_thread = threading.Thread(target=self._keep_alive)
        self._running = True
        self._keep_alive_thread.setDaemon(True)
        self._keep_alive_thread.start()
    
    def stop(self):
        self._running = False

    def update_status(self, status:ctap.constants.CTAPHID_KEEPALIVE_STATUS):
        log.debug("Keep-alive status updated")
        self._status = status
        self._send_keep_alive()

    def _send_keep_alive(self):
        self._ctaphid.send_keep_alive_response(CTAPHIDKeepAliveResponse(self._cid,self._status))

    def _keep_alive(self):

        while self._running:
            self._send_keep_alive()
            time.sleep(self._interval)
            self._elapsed = self._elapsed + self._interval
            if self._elapsed > self._max:
                log.debug("Max keep-alive exceeded - will stop")
                self._running = False
        log.debug("Keep-alive ended")
        self._cid = None 