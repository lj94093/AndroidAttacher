#!/usr/bin/env python
# ! -*- coding: utf-8 -*-

import os
import subprocess
import logging

import idaapi
import idc
import ida_kernwin
import sys
def get_plugin_home():
    import inspect

    plugin_path = os.path.abspath(inspect.getfile(inspect.currentframe()))
    if os.path.islink(plugin_path):
        plugin_path = os.readlink(plugin_path)

    return os.path.dirname(plugin_path)

sys.path.append(get_plugin_home())


def init_log(logFile="", isLog2File = False):
    if isLog2File is False:
        filename = None
        stream = sys.stdout
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s %(filename)-22s[line:%(lineno)-4d] %(levelname)-6s %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            stream=stream,
            filemode="w",
        )
    else:
        stream = None
        filename = logFile
        if logFile is None:
            filename = "wrapper.log"
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s %(filename)-22s[line:%(lineno)-4d] %(levelname)-6s %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            filename=filename,
            filemode="w",
        )

class android_attacher_plugin(idaapi.plugin_t):
    init_log()
    ACTION_NAME = "Attach to Android app"

    flags = idaapi.PLUGIN_KEEP
    comment = ""
    wanted_name = "Android Debug Attach"
    wanted_hotkey = "Alt-F8"
    help = wanted_name + ": Debugger/" + ACTION_NAME

    def init(self):
        # put import in code block for hot laod
        from aaf import utils
        architecture = utils.getIdaArchitecture()
        if architecture != "arm":
            logging.info("%s unsupported architecture: %s" % (self.wanted_name, architecture))
            return idaapi.PLUGIN_SKIP

        ida_kernwin.msg("Initializing %s\n" % self.wanted_name)

        from aaf import adb
        wrapper = adb.AdbWrapper("")

        from aaf import AndroidAttacher
        utilsJar = os.path.join(get_plugin_home(), "aaf", "utils.jar")
        config_file = os.path.splitext(idc.get_idb_path())[0] + ".aaf.conf"
        self.androidAttacher = AndroidAttacher(wrapper, utilsJar, config_file)
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg=0):
        self.androidAttacher.attach()


def PLUGIN_ENTRY():
    return android_attacher_plugin()
