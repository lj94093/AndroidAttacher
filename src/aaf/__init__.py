#!/usr/bin/env python
# ! -*- coding: utf-8 -*-

import hashlib
import json
import os
import re
import subprocess
import threading
import time
import ida_dbg
import ida_kernwin
import idc
from aaf import utils
import logging

class AndroidAttacher(object):
    def __init__(self, wrapper, utilsJar, config_file):

        self.packageName = None
        self.launchActivity = None
        self.android_server = None
        self.device = None
        self.adb = wrapper
        self.utilsJar = utilsJar
        self.config_file = config_file
        if hasattr(idc, "idadir"):
            # ida 7.0
            self.bindir = os.path.abspath(idc.idadir() + "/dbgsrv")
        else:
            import idaapi
            self.bindir = os.path.abspath(idaapi.get_idcpath() + "/../dbgsrv")

    def load_config(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "r") as f:
                    return json.load(f, encoding="UTF-8")
            except Exception as e:
                logging.exception(e)
        return {}

    def save_config(self, obj):
        try:
            with open(self.config_file, "w") as f:
                json.dump(obj, f, ensure_ascii=False)
        except Exception as e:
            logging.exception(e)


    def _chooseDevice(self):
        self.device = self.adb.chooseDevice(self.device)
        logging.info('Using device %s' % self.device)


    def _getPid(self):
        ps = self.adb.call(['shell', 'ps']).splitlines()
        for x in ps:
            xs = x.split()
            if self.packageName in xs and ('S' in xs or 'T' in xs):
                g = (col for col in xs if col.isdigit())
                return int(next(g))


    def _launch(self, debug):
        start = time.time()
        ida_kernwin.msg('Launching %s/%s... ' % (self.packageName, self.launchActivity))

        args = ['shell', 'am', 'start', '-n', self.packageName + '/' + self.launchActivity, '-W']
        if debug:
            args.append("-D")

        proc = self.adb.call(args, stderr=subprocess.PIPE, async=True, preexec_fn=utils.androidServerPreExec)

        def watchdog():
            time.sleep(15)
            if proc.poll() is None:  # still running
                proc.terminate()

        (threading.Thread(target=watchdog)).start()

        for _ in range(50):
            time.sleep(0.2)
            if self._getPid():
                break
        logging.info("Done in %s seconds" % (time.time() - start))


    def _attach(self, debug):
        pid = self._getPid()
        if not pid:
            self._launch(debug)

            for _ in range(10):
                pid = self._getPid()
                if pid:
                    break
                time.sleep(0.5)

        if not pid:
            raise Exception("Error attach %s/%s." % (self.packageName, self.launchActivity))
        self.attach_app(pid)
        if debug:
            self.adb.forward('tcp:8700' , 'jdwp:' + str(pid))
            from aaf import DBGHook
            self.dbg_hook=DBGHook.DBG_Hook()
            self.dbg_hook.hook()


    def attach_app(self, pid):
        ida_dbg.load_debugger("armlinux", 1)
        ida_dbg.set_remote_debugger("localhost", "", self.port)
        status = ida_dbg.attach_process(pid, -1)
        if status == 1:
            logging.info('Attaching to pid %s... Done' % pid)
        else:
            logging.info('Attaching to pid %s... Failed: %s' % (pid, status))

    def _chooseLaunchActivity(self, packageName):
        '''
    packageApk = self.device.getApkPath(packageName)
    if not packageApk:
      raise StandardError("Error find package apk: %s." % packageName)
    '''
        activities=[]
        aaf_utils = "/data/local/tmp/aaf_utils.jar"
        # logging.info "Pushing utils.jar to device: %s" % aaf_utils
        self.adb.push(self.utilsJar, aaf_utils)
        try:
            out = self.adb.call(['shell', 'su', 'root',
                             '"dalvikvm -cp ' + aaf_utils + ' com.android.internal.util.WithFramework com.fuzhu8.aaf.GetMainActivity ' + packageName + '"'])
            resp = json.loads(out)
            if resp["code"] != 0:
                raise Exception(resp["msg"])
            main = utils.decode_list(resp["main"])
            if len(main) == 1:
                return main[0]
            activities = utils.decode_list(resp["activities"])
            if len(activities) == 1:
                return activities[0]
        except Exception as e:
            out = self.adb.call(['shell',"monkey -p %s -v -v -v 0"%packageName])
            
            for line in out.splitlines():
                if "from package %s"%packageName in line:
                    activities.append(re.search("main activity (.*?) ",line).group(1))
            logging.info(activities)

        return utils.ChooserForm("Choose activity", activities).choose()

    def _startAndroidServer(self, app_64=False,skipShell=False, redirectOut=False):
        global androidServerSuOut
        global port

        ida_port = '-p' + str(self.android_server_port)
        server_name='android_server'
        if app_64:
            server_name+="64"
        ps = self.adb.call(['shell', 'ps']).splitlines()
        for proc in [x.split() for x in ps if server_name in x]:
            pid = next((col for col in proc if col.isdigit()))
            cmdline = self.adb.call(['shell', 'cat', '/proc/' + pid + '/cmdline']).split('\0')
            if ida_port not in cmdline:
                continue
            self.adb.call(['shell', 'su', 'root', 'kill' ,'-9',str(pid)])

        localServerPath = os.path.join(self.bindir, server_name)
        
        androidServerPath = '/data/local/tmp/'+server_name
        lines = self.adb.call(["shell", "ls","-l", os.path.dirname(androidServerPath),"|","grep",server_name+"$"]).splitlines()
        if len(lines)==0 or len(lines[0])==0:
            logging.info("Pushing android_server to device: %s" % androidServerPath)
            self.adb.push(localServerPath, androidServerPath)
            self.adb.call(['shell', 'chmod', '755', androidServerPath])

        args = [ida_port]

        def runAndroidServer(args):  # returns (proc, port, stdout)
            # print "runAndroidServer:", args
            proc = self.adb.call(args, stderr=subprocess.PIPE, async=True, preexec_fn=utils.androidServerPreExec)
            kill_watchdog = False

            def watchdog():
                time.sleep(180)
                if kill_watchdog and proc.poll() is None:  # still running
                    proc.terminate()

            (threading.Thread(target=watchdog)).start()

            # we have to find the port used by android_server from stdout
            # while this complicates things a little, it allows us to
            # have multiple android_servers running

            # Listening on port #23946...
            # Listening on 0.0.0.0:23946...
            out = []
            line = ' '
            while 1:
                try:
                    line = proc.stdout.readline().decode("utf8")
                    # words = line.split()
                    # print "line:", line, "words:", words
                    out.append(line.rstrip())
                    if 'android_server terminated by' in line:
                        logging.info("android_server terminated by")
                        break
                    if 'Listening' not in line:
                        logging.info("not Listening")
                        continue
                    if "Address already in use" in line:
                        logging.info(line)
                        break
                    if '#' in line:
                        start_index = line.index("#")
                    elif ':' in line:
                        start_index = line.index(":")
                    else:
                        logging.info("parse line failed: ", line)
                        continue
                    end_index = line.index("...")
                    port = line[start_index + 1: end_index]

                    if not port.isdigit():
                        logging.info("parse failed: port=", port, ", line=", line)
                        continue
                    kill_watchdog = True
                    logging.info("normal exit watchdog")
                    return (proc, port, out)
                except BaseException as e:
                    logging.exception(e)
            # not found, error?
            kill_watchdog = True
            return (None, None, out)

        # can we run as root?
        androidServerProc = None
        if not androidServerProc:
            logging.info('run as root:adb shell su root "%s"'%" ".join([androidServerPath] + args))
            cmd=['shell', 'su' ,'root',androidServerPath]
            if args:
                cmd.extend(args)
            (androidServerProc, port, androidServerSuOut) = runAndroidServer(cmd)


        if not androidServerProc:
            logging.info('"su root" output:')
            logging.info(' ' + '\n '.join([s for s in androidServerSuOut if s]).replace('\0', ''))
            raise Exception('failed to run android_server')

        self.port = int(port)
        self.android_server = androidServerProc

        # forward the port that android_server gave us
        self.adb.forward('tcp:' + port, 'tcp:' + port)
        logging.info('Done')

    def attach(self):
        try:
            logging.info("start to attach")
            import idaapi
            if idaapi.is_debugger_on():
                logging.info("Already in debug mode.")
                return

            is_running = self.android_server and self.android_server.poll() is None
            if self.device is None or not is_running:
                self._chooseDevice()

            config = self.load_config()
            av = utils.AttachView(self.device.getPackageNames(),
                                  config["packageName"] if "packageName" in config else "")
            ret = av.show(config["idaDebugPort"] if "idaDebugPort" in config else 23946,
                          config["debug"] if "debug" in config else False,
                          config["app_64"] if "app_64" in config else False)
            if not ret:
                return
            (packageName, idaDebugPort, debug ,app_64) = ret

            if idaDebugPort < 1024:
                logging.info("Attach %s failed with ida debug port: %s" % (packageName, idaDebugPort))
                return
            self.save_config({"packageName": packageName, "idaDebugPort": idaDebugPort, "debug": debug})

            if self.launchActivity is None or self.packageName != packageName:
                self.launchActivity = self._chooseLaunchActivity(packageName)

            self.packageName = packageName
            self.android_server_port = idaDebugPort

            if not self.launchActivity:
                return

            logging.info("Request attach:%s"%packageName)

            if is_running:
                self._attach(debug)
                return

            self._startAndroidServer(app_64)
            self._attach(debug)
        except BaseException as e:
            logging.exception(e)
            if self.android_server and self.android_server.poll() is None:
                self.android_server.terminate()
                
                logging.info('Terminated android_server.')
                self.android_server = None
