#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import ctypes
import errno
import json
import fcntl
from multiprocessing import Process
import os
import pprint
import random
import re
import time
import termios
import select
import struct
import string
import socket
import subprocess
import sys
import unittest


from lib import YnlFamily, NlError


class PSPExceptShortIO(Exception):
    pass


CLONE_NEWNS  = 0x00020000
CLONE_NEWNET = 0x40000000


libc = ctypes.cdll.LoadLibrary('libc.so.6')
cfg = None


class cmd:
    def __init__(self, comm, shell=True, fail=True, ns=None, background=False):
        if ns:
            if isinstance(ns, NetNS):
                ns = ns.name
            comm = f'ip netns exec {ns} ' + comm

        self.stdout = None
        self.stderr = None
        self.ret = None

        self.comm = comm
        self.proc = subprocess.Popen(comm, shell=shell, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
        if not background:
            self.process(terminate=False, fail=fail)

    def process(self, terminate=True, fail=None):
        if terminate:
            self.proc.terminate()
        stdout, stderr = self.proc.communicate()
        self.stdout = stdout.decode("utf-8")
        self.stderr = stderr.decode("utf-8")
        self.proc.stdout.close()
        self.proc.stderr.close()
        self.ret = self.proc.returncode

        if self.proc.returncode != 0 and fail:
            if len(stderr) > 0 and stderr[-1] == "\n":
                stderr = stderr[:-1]
            raise Exception("Command failed: %s\n%s" % (self.proc.args, stderr))


def ip(args, ns=None):
    return cmd("ip " + args, ns=ns)


def v(*args):
    global cfg
    if cfg and cfg.verbose:
        print(*args, flush=True)


def recv_careful(tcfg, s, target, rounds=20):
    data = b''
    for i in range(rounds):
        try:
            data += s.recv(target - len(data), socket.MSG_DONTWAIT)
            if len(data) == target:
                return data
        except BlockingIOError:
            time.sleep(0.001)
    raise PSPExceptShortIO(target, len(data), data)


def send_careful(tcfg, s, rounds):
    data = b'0123456789' * 200
    for i in range(rounds):
        n = 0
        retries = 0
        while True:
            try:
                n += s.send(data[n:], socket.MSG_DONTWAIT)
                if n == len(data):
                    break
            except BlockingIOError:
                time.sleep(0.05)

            retries += 1
            if (tcfg and tcfg.verbose) or retries > 10:
                rlen = tcfg.remote_read_len()
                report = f'sent: {i * len(data) + n} remote len: {rlen}'
                v('Short send:', n, 'already', report)
                if retries > 10:
                    raise Exception(report)

    v("Sent ", len(data) * rounds)
    return len(data) * rounds


class NetdevSim:
    """
    Class for netdevsim netdevice and its attributes.
    """

    def __init__(self, nsimdev, port_index, ifname, ns=None):
        # In case udev renamed the netdev to according to new schema,
        # check if the name matches the port_index.
        nsimnamere = re.compile("eni\d+np(\d+)")
        match = nsimnamere.match(ifname)
        if match and int(match.groups()[0]) != port_index + 1:
            raise Exception("netdevice name mismatches the expected one")

        self.ifname = ifname
        self.nsimdev = nsimdev
        self.port_index = port_index
        self.ns = ns
        self.dfs_dir = "%s/ports/%u/" % (nsimdev.dfs_dir, port_index)
        ret = ip("-j link show dev %s" % ifname, ns=ns)
        self.dev = json.loads(ret.stdout)[0]

    def dfs_write(self, path, val):
        self.nsimdev.dfs_write(f'ports/{self.port_index}/' + path, val)


class NetdevSimDev:
    """
    Class for netdevsim bus device and its attributes.
    """
    @staticmethod
    def ctrl_write(path, val):
        fullpath = os.path.join("/sys/bus/netdevsim/", path)
        try:
            with open(fullpath, "w") as f:
                f.write(val)
        except OSError as e:
            v("WRITE %s: %r" % (fullpath, val), -e.errno)
            raise e
        v("WRITE %s: %r" % (fullpath, val), 0)

    def dfs_write(self, path, val):
        fullpath = os.path.join(f"/sys/kernel/debug/netdevsim/netdevsim{self.addr}/", path)
        try:
            with open(fullpath, "w") as f:
                f.write(val)
        except OSError as e:
            v("WRITE %s: %r" % (fullpath, val), -e.errno)
            raise e
        v("WRITE %s: %r" % (fullpath, val), 0)

    def __init__(self, port_count=1, ns=None):
        # nsim will spawn in init_net, we'll set to actual ns once we switch it the.sre
        self.ns = None

        if not os.path.exists("/sys/bus/netdevsim"):
            cmd("modprobe netdevsim")

        addr = random.randrange(1 << 15)
        while True:
            try:
                self.ctrl_write("new_device", "%u %u" % (addr, port_count))
            except OSError as e:
                if e.errno == errno.ENOSPC:
                    addr = random.randrange(1 << 15)
                    continue
                raise e
            break
        self.addr = addr

        # As probe of netdevsim device might happen from a workqueue,
        # so wait here until all netdevs appear.
        self.wait_for_netdevs(port_count)

        if ns:
            cmd(f"devlink dev reload netdevsim/netdevsim{addr} netns {ns.name}")
            self.ns = ns

        cmd("udevadm settle", ns=self.ns)
        ifnames = self.get_ifnames()

        self.dfs_dir = "/sys/kernel/debug/netdevsim/netdevsim%u/" % addr

        self.nsims = []
        for port_index in range(port_count):
            self.nsims.append(NetdevSim(self, port_index, ifnames[port_index],
                                        ns=ns))

    def get_ifnames(self):
        ifnames = []
        listdir = cmd(f"ls /sys/bus/netdevsim/devices/netdevsim{self.addr}/net/",
                      ns=self.ns).stdout.split()
        for ifname in listdir:
            ifnames.append(ifname)
        ifnames.sort()
        return ifnames

    def wait_for_netdevs(self, port_count):
        timeout = 5
        timeout_start = time.time()

        while True:
            try:
                ifnames = self.get_ifnames()
            except FileNotFoundError as e:
                ifnames = []
            if len(ifnames) == port_count:
                break
            if time.time() < timeout_start + timeout:
                continue
            raise Exception("netdevices did not appear within timeout")

    def remove(self):
        self.ctrl_write("del_device", "%u" % (self.addr, ))

    def remove_nsim(self, nsim):
        self.nsims.remove(nsim)
        self.ctrl_write("devices/netdevsim%u/del_port" % (self.addr, ),
                        "%u" % (nsim.port_index, ))


class PSPtestBase(unittest.TestCase):

    def test_list_devices(self):
        """ Dump all devices """
        devices = cfg.ynl.dev_get({}, dump=True)
        v('Devices:', devices)

        found = False
        for dev in devices:
            found |= dev['id'] == cfg.psp_dev_id
        self.assertTrue(found)

    def test_get_device(self):
        """ Get the device we intend to use """
        dev = cfg.ynl.dev_get({'id': cfg.psp_dev_id})
        v('Device:', dev)
        self.assertEqual(dev['id'], cfg.psp_dev_id)

    def test_get_device_bad(self):
        """ Test getting device which doesn't exist """
        with self.assertRaises(NlError) as cm:
            cfg.ynl.dev_get({'id': cfg.psp_dev_id + 1234567})

        the_exception = cm.exception
        self.assertEqual(the_exception.nl_msg.error, -19)

    def test_rotate(self):
        """ Test key rotation """
        rot = cfg.ynl.key_rotate({"id": cfg.psp_dev_id})
        self.assertEqual(rot['id'], cfg.psp_dev_id)
        rot = cfg.ynl.key_rotate({"id": cfg.psp_dev_id})
        self.assertEqual(rot['id'], cfg.psp_dev_id)

    def test_rotate_spi(self):
        """ Test key rotation and SPI check """
        topA = topB = 0
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            assocA = cfg.ynl.rx_assoc({"version": 0,
                                       "dev-id": cfg.psp_dev_id,
                                       "sock-fd": s.fileno()})
            topA = assocA['rx-key']['spi'] >> 31
            s.close()
        rot = cfg.ynl.key_rotate({"id": cfg.psp_dev_id})
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            self.assertEqual(rot['id'], cfg.psp_dev_id)
            assocB = cfg.ynl.rx_assoc({"version": 0,
                                       "dev-id": cfg.psp_dev_id,
                                       "sock-fd": s.fileno()})
            topB = assocB['rx-key']['spi'] >> 31
            s.close()
        self.assertNotEqual(topA, topB)


class PSPtestAssoc(unittest.TestCase):

    def test_assoc(self):
        """ Test creating associations """
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            assoc = cfg.ynl.rx_assoc({"version": 0,
                                      "dev-id": cfg.psp_dev_id,
                                      "sock-fd": s.fileno()})
            v('Rx assoc:', assoc)
            self.assertEqual(assoc['version'], 'hdr0-aes-gcm-128')
            self.assertEqual(assoc['dev-id'], cfg.psp_dev_id)
            self.assertGreater(assoc['rx-key']['spi'], 0)
            self.assertEqual(len(assoc['rx-key']['key']), 16)

            assoc = cfg.ynl.tx_assoc({"dev-id": cfg.psp_dev_id,
                                      "version": 0,
                                      "tx-key": assoc['rx-key'],
                                      "sock-fd": s.fileno()})
            v('Tx assoc:', assoc)
            self.assertEqual(len(assoc), 0)
            s.close()

    def test_assoc_bad_dev(self):
        """ Test creating associations with bad device ID """
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            with self.assertRaises(NlError) as cm:
                cfg.ynl.rx_assoc({"version": 0,
                                  "dev-id": cfg.psp_dev_id + 1234567,
                                  "sock-fd": s.fileno()})
            the_exception = cm.exception
            self.assertEqual(the_exception.nl_msg.error, -19)

    def test_assoc_sk_only_conn(self):
        """ Test creating associations based on socket """
        with cfg.make_clr_conn() as s:
            assoc = cfg.ynl.rx_assoc({"version": 0,
                                      "sock-fd": s.fileno()})
            self.assertEqual(assoc['dev-id'], cfg.psp_dev_id)
            cfg.ynl.tx_assoc({"version": 0,
                              "tx-key": assoc['rx-key'],
                              "sock-fd": s.fileno()})
            cfg.close_conn(s)

    def test_assoc_sk_only_mismatch(self):
        """ Test creating associations based on socket (dev mismatch) """
        with cfg.make_clr_conn() as s:
            with self.assertRaises(NlError) as cm:
                cfg.ynl.rx_assoc({"version": 0,
                                  "dev-id": cfg.psp_dev_id + 1234567,
                                  "sock-fd": s.fileno()})
            the_exception = cm.exception
            self.assertEqual(the_exception.nl_msg.extack['bad-attr'], ".dev-id")
            self.assertEqual(the_exception.nl_msg.error, -22)

    def test_assoc_sk_only_mismatch_tx(self):
        """ Test creating associations based on socket (dev mismatch) """
        with cfg.make_clr_conn() as s:
            with self.assertRaises(NlError) as cm:
                assoc = cfg.ynl.rx_assoc({"version": 0,
                                          "sock-fd": s.fileno()})
                cfg.ynl.tx_assoc({"version": 0,
                                  "tx-key": assoc['rx-key'],
                                  "dev-id": cfg.psp_dev_id + 1234567,
                                  "sock-fd": s.fileno()})
            the_exception = cm.exception
            self.assertEqual(the_exception.nl_msg.extack['bad-attr'], ".dev-id")
            self.assertEqual(the_exception.nl_msg.error, -22)

    def test_assoc_sk_only_unconn(self):
        """ Test creating associations based on socket (unconnected, should fail) """
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            with self.assertRaises(NlError) as cm:
                cfg.ynl.rx_assoc({"version": 0,
                                  "sock-fd": s.fileno()})
            the_exception = cm.exception
            self.assertEqual(the_exception.nl_msg.extack['miss-type'], "dev-id")
            self.assertEqual(the_exception.nl_msg.error, -22)

    def test_assoc_mismatch(self):
        """ Test creating associations with bad params Rx vs Tx """
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            assoc = cfg.ynl.rx_assoc({"version": 0,
                                      "dev-id": cfg.psp_dev_id,
                                      "sock-fd": s.fileno()})
            v('Rx assoc:', assoc)
            self.assertEqual(assoc['version'], 'hdr0-aes-gcm-128')
            self.assertEqual(assoc['dev-id'], cfg.psp_dev_id)
            self.assertGreater(assoc['rx-key']['spi'], 0)
            self.assertEqual(len(assoc['rx-key']['key']), 16)

            # Rx and Tx version mismatch
            with self.assertRaises(NlError) as cm:
                cfg.ynl.tx_assoc({"dev-id": cfg.psp_dev_id,
                                  "version": 1,
                                  "tx-key": assoc['rx-key'],
                                  "sock-fd": s.fileno()})
            the_exception = cm.exception
            self.assertEqual(the_exception.nl_msg.error, -22)

            s.close()

    def test_assoc_twice(self):
        """ Test reusing Tx assoc for two sockets """
        def rx_assoc_check(s):
            assoc = cfg.ynl.rx_assoc({"version": 0,
                                      "dev-id": cfg.psp_dev_id,
                                      "sock-fd": s.fileno()})
            v('Rx assoc:', assoc)
            self.assertEqual(assoc['version'], 'hdr0-aes-gcm-128')
            self.assertEqual(assoc['dev-id'], cfg.psp_dev_id)
            self.assertGreater(assoc['rx-key']['spi'], 0)
            self.assertEqual(len(assoc['rx-key']['key']), 16)

            return assoc

        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            assoc = rx_assoc_check(s)
            tx = cfg.ynl.tx_assoc({"dev-id": cfg.psp_dev_id,
                                   "version": 0,
                                   "tx-key": assoc['rx-key'],
                                   "sock-fd": s.fileno()})
            v('Tx assoc:', tx)
            self.assertEqual(len(tx), 0)

            # Use the same Tx assoc second time
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s2:
                rx_assoc_check(s2)
                tx = cfg.ynl.tx_assoc({"dev-id": cfg.psp_dev_id,
                                       "version": 0,
                                       "tx-key": assoc['rx-key'],
                                       "sock-fd": s2.fileno()})
                v('Tx assoc:', tx)
                self.assertEqual(len(tx), 0)

            s.close()


class PSPtestData(unittest.TestCase):

    def _check_data_rx(self, exp_len):
        read_len = -1
        for i in range(30):
            cfg.comm_sock.send(b'read len\0')
            read_len = int(cfg.comm_sock.recv(1024)[:-1].decode('utf-8'))
            if read_len == exp_len:
                break
            time.sleep(0.01)
        self.assertEqual(read_len, exp_len)

    def _check_data_outq(self, s, exp_len, force_wait=False):
        outq = 0
        for i in range(10):
            one = b'\0' * 4
            data = fcntl.ioctl(s.fileno(), termios.TIOCOUTQ, one)
            outq = struct.unpack("I", data)[0]
            if not force_wait and outq == exp_len:
                break
            time.sleep(0.01)
        self.assertEqual(outq, exp_len)

    def _get_stat(self, key):
        return cfg.ynl.get_stats({'dev-id': cfg.psp_dev_id})[key]

    def test_send_bad_key(self):
        """ Test send data with bad key """
        s = cfg.make_psp_conn()

        rx_assoc = cfg.ynl.rx_assoc({"version": 0,
                                     "dev-id": cfg.psp_dev_id,
                                     "sock-fd": s.fileno()})
        rx = rx_assoc['rx-key']
        v('Local SPI:', rx['spi'], 'key:', rx['key'])
        tx = spi_xchg(s, rx)
        v('Remote SPI:', tx['spi'], 'key:', tx['key'])
        tx['key'] = (tx['key'][0] ^ 0xff).to_bytes(1, 'little') + tx['key'][1:]
        v('Broken SPI:', tx['spi'], 'key:', tx['key'])

        # Make sure we accept the ACK for the SPI before we seal with the bad key
        self._check_data_outq(s, 0)

        cfg.ynl.tx_assoc({"dev-id": cfg.psp_dev_id,
                          "version": 0,
                          "tx-key": tx,
                          "sock-fd": s.fileno()})

        data_len = send_careful(cfg, s, 20)
        self._check_data_outq(s, data_len, force_wait=True)
        self._check_data_rx(0)
        cfg.close_psp_conn(s)

    def test_send(self):
        """ Test basic data send """
        s = cfg.make_psp_conn()

        rx_assoc = cfg.ynl.rx_assoc({"version": 0,
                                     "dev-id": cfg.psp_dev_id,
                                     "sock-fd": s.fileno()})
        rx = rx_assoc['rx-key']
        v('Local SPI:', rx['spi'], 'key:', rx['key'])
        tx = spi_xchg(s, rx)
        v('Remote SPI:', tx['spi'], 'key:', tx['key'])

        cfg.ynl.tx_assoc({"dev-id": cfg.psp_dev_id,
                          "version": 0,
                          "tx-key": tx,
                          "sock-fd": s.fileno()})

        data_len = send_careful(cfg, s, 100)
        self._check_data_rx(data_len)
        cfg.close_psp_conn(s)

    def test_send_disconnect(self):
        with cfg.make_psp_conn() as s:
            assoc = cfg.ynl.rx_assoc({"version": 0,
                                      "sock-fd": s.fileno()})
            tx = spi_xchg(s, assoc['rx-key'])
            cfg.ynl.tx_assoc({"version": 0,
                              "tx-key": tx,
                              "sock-fd": s.fileno()})

            data_len = send_careful(cfg, s, 100)
            self._check_data_rx(data_len)

            s.shutdown(socket.SHUT_RDWR)
            s.close()

    def test_mss_adjust(self):
        """ Test that kernel auto-adjusts MSS """

        # First figure out what the MSS would be without any adjustments
        s = cfg.make_clr_conn()
        s.send(b"0123456789abcdef" * 1024)
        self._check_data_rx(16 * 1024)
        mss = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
        v("Base MSS", mss)
        cfg.close_conn(s)

        s = cfg.make_psp_conn()
        try:
            rx_assoc = cfg.ynl.rx_assoc({"version": 0,
                                         "dev-id": cfg.psp_dev_id,
                                         "sock-fd": s.fileno()})
            rx = rx_assoc['rx-key']
            v('Local SPI:', rx['spi'], 'key:', rx['key'])
            tx = spi_xchg(s, rx)
            v('Remote SPI:', tx['spi'], 'key:', tx['key'])

            rxmss = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
            v("MSS with Rx assoc", rxmss)
            self.assertEqual(mss, rxmss)

            cfg.ynl.tx_assoc({"dev-id": cfg.psp_dev_id,
                              "version": 0,
                              "tx-key": tx,
                              "sock-fd": s.fileno()})

            txmss = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
            v("MSS with Tx assoc, data", txmss)
            self.assertEqual(mss, txmss + 32)

            data_len = send_careful(cfg, s, 100)
            self._check_data_rx(data_len)
            self._check_data_outq(s, 0)

            txmss = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
            v("MSS with Tx assoc, data", txmss)
            self.assertEqual(mss, txmss + 32)
        finally:
            cfg.close_psp_conn(s)

    def test_stale_key(self):
        """ Test send on a double-rotated key """

        prev_stale = self._get_stat('stale-events')

        s = cfg.make_psp_conn()
        try:
            rx_assoc = cfg.ynl.rx_assoc({"version": 0,
                                         "dev-id": cfg.psp_dev_id,
                                         "sock-fd": s.fileno()})
            rx = rx_assoc['rx-key']
            v('Local SPI:', rx['spi'], 'key:', rx['key'])
            tx = spi_xchg(s, rx)
            v('Remote SPI:', tx['spi'], 'key:', tx['key'])

            cfg.ynl.tx_assoc({"dev-id": cfg.psp_dev_id,
                              "version": 0,
                              "tx-key": tx,
                              "sock-fd": s.fileno()})

            data_len = send_careful(cfg, s, 100)
            self._check_data_rx(data_len)
            self._check_data_outq(s, 0)

            v("# Rotate (x2):")
            rot = cfg.ynl.key_rotate({"id": cfg.psp_dev_id})
            v('  ', rot)
            rot = cfg.ynl.key_rotate({"id": cfg.psp_dev_id})
            v('  ', rot)

            cur_stale = self._get_stat('stale-events')
            self.assertGreater(cur_stale, prev_stale)

            n = s.send(b'0123456789' * 200)
            v("Queued", n)
            self._check_data_outq(s, 2000, force_wait=True)
        finally:
            cfg.close_psp_conn(s)

    def test_send_off(self):
        """ Test data send when PSP is turned off """

        s = info = udps = None
        try:
            s = cfg.make_psp_conn()

            rx_assoc = cfg.ynl.rx_assoc({"version": 0,
                                         "sock-fd": s.fileno()})
            tx = spi_xchg(s, rx_assoc['rx-key'])
            cfg.ynl.tx_assoc({"version": 0,
                              "tx-key": tx,
                              "sock-fd": s.fileno()})

            cfg.req_echo(s)

            info = cfg.ynl.dev_get({"id": cfg.psp_dev_id})
            cfg.ynl.dev_set({"id": cfg.psp_dev_id,
                             "psp-versions-ena": 0})

            # Try to catch the still-encapsulated PSP packets on a UDP socket
            udps = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            udps.bind(('::', 1000))

            cfg.req_echo(s, expect_fail=True)

            cfg.ynl.dev_set({"id": cfg.psp_dev_id,
                             "psp-versions-ena": info['psp-versions-ena']})
            info = None
            # We need some more TCP RTOs so lots of rounds
            recv_careful(cfg, s, 5, rounds=250)

            # Will raise BlockingIOError if there are no packets
            udps.recv(8192, socket.MSG_DONTWAIT)
        finally:
            if s:
                cfg.close_psp_conn(s)
            if info:
                cfg.ynl.dev_set({"id": cfg.psp_dev_id,
                                 "psp-versions-ena": info['psp-versions-ena']})
            if udps:
                udps.close()


class PSPtestDeviceRemoval(unittest.TestCase):

    def __nsim_psp_rereg(self):
        global cfg

        # The PSP dev ID will change, remember what was there before
        before = set([x['id'] for x in cfg.ynl.dev_get({}, dump=True)])

        cfg.nsim.nsims[0].dfs_write('psp_rereg', '1')

        after = set([x['id'] for x in cfg.ynl.dev_get({}, dump=True)])

        new_devs = list(after - before)
        self.assertEqual(len(new_devs), 1)
        cfg.psp_dev_id = list(after - before)[0]

    def test_device_removal_rx(self):
        """ Test removing a netdev / PSD with active Rx assoc """

        # We could technically devlink reload real devices, too
        # but that kills the control socket. So test this on
        # netdevsim only for now
        if not hasattr(cfg, "nsim"):
            return

        s = cfg.make_clr_conn()
        try:
            rx_assoc = cfg.ynl.rx_assoc({"version": 0,
                                         "dev-id": cfg.psp_dev_id,
                                         "sock-fd": s.fileno()})
            self.assertIsNotNone(rx_assoc)

            self.__nsim_psp_rereg()
        finally:
            cfg.close_conn(s)

    def test_device_removal_bi(self):
        """ Test removing a netdev / PSD with active Rx/Tx assoc """

        # We could technically devlink reload real devices, too
        # but that kills the control socket. So test this on
        # netdevsim only for now
        if not hasattr(cfg, "nsim"):
            return

        s = cfg.make_clr_conn()
        try:
            rx_assoc = cfg.ynl.rx_assoc({"version": 0,
                                         "dev-id": cfg.psp_dev_id,
                                         "sock-fd": s.fileno()})
            cfg.ynl.tx_assoc({"dev-id": cfg.psp_dev_id,
                              "version": 0,
                              "tx-key": rx_assoc['rx-key'],
                              "sock-fd": s.fileno()})
            self.__nsim_psp_rereg()
        finally:
            cfg.close_conn(s)


def spi_xchg(s, rx):
    s.send(struct.pack('I', rx['spi']) + rx['key'])
    tx = s.recv(4 + len(rx['key']))
    return {
        'spi': struct.unpack('I', tx[:4])[0],
        'key': tx[4:]
    }


def conn_setup_psp(cfg, s):
    rx_assoc = cfg.ynl.rx_assoc({"version": 0,
                                 "dev-id": cfg.psp_dev_id,
                                 "sock-fd": s.fileno()})
    rx = rx_assoc['rx-key']
    v('Local SPI:', rx['spi'], 'key:', rx['key'])
    tx = spi_xchg(s, rx)
    v('Remote SPI:', tx['spi'], 'key:', tx['key'])
    cfg.ynl.tx_assoc({"dev-id": cfg.psp_dev_id,
                      "version": 0,
                      "tx-key": tx,
                      "sock-fd": s.fileno()})


def server(cfg):
    cmd_cnt = 0
    socks = [cfg.server, cfg.comm_sock]
    data_sock = None
    data_read = None
    accept_cfg = None
    while True:
        rsocks, _, _, = select.select(socks, [], [], 1)

        if data_sock in rsocks:
            data = data_sock.recv(8196)
            if not data:
                data_sock.close()
                socks.remove(data_sock)
                data_sock = None
            else:
                data_read += len(data)

        if cfg.comm_sock in rsocks:
            sock = cfg.comm_sock
            data = sock.recv(4096)
            if not data:
                if cmd_cnt == 0:
                    raise Exception("Finished without any work")
                return
            data_reqs = data[:-1].split(b'\0')
            for data in data_reqs:
                reply = b'ack\0'
                if data == b'read len':
                    reply = str(data_read).encode('utf-8') + b'\0'
                elif data == b'data echo':
                    if data_sock:
                        data_sock.send(b'echo\0')
                    else:
                        print("SERVER: echo but no data sock")
                elif data == b'data close':
                    if data_sock:
                        data_sock.close()
                        socks.remove(data_sock)
                        data_sock = None
                    else:
                        reply = b'err\0'
                        print('SERVER: close but no data sock')
                elif data == b'conn psp':
                    accept_cfg = b'psp'
                elif data == b'conn clr':
                    accept_cfg = b'clr'
                else:
                    reply = b'err\0'
                    print('SERVER: unknown command', data)
                if reply:
                    sock.send(reply)
                cmd_cnt += 1

        if cfg.server in rsocks:
            if data_sock:
                print('SERVER: new data sock but old one still here')
                data_sock.close()
                socks.remove(data_sock)
            data_sock, _ = cfg.server.accept()
            data_read = 0
            socks.append(data_sock)
            if accept_cfg == b'psp':
                conn_setup_psp(cfg, data_sock)
            elif accept_cfg == b'clr':
                pass
            else:
                print('SERVER: Data connection with no config')


class NetNS:
    def __init__(self, name=None):
        if name:
            self.name = name
        else:
            self.name = ''.join(random.choice(string.ascii_lowercase) for _ in range(8))
        ip('netns add ' + self.name)

    def __del__(self):
        ip('netns del ' + self.name)

    def enter(self):
        with open("/var/run/netns/" + self.name) as nsfd:
            libc.setns(nsfd.fileno(), CLONE_NEWNET)
        if libc.unshare(CLONE_NEWNS) < 0:
            raise Exception("unshare failed")
        cmd("mount --make-rslave /")
        cmd("umount -l /sys")
        cmd("mount -t sysfs none /sys")
        cmd("mount -t debugfs none /sys/kernel/debug")


class TestConfig:
    def __init__(self, netns=None, ns_id=0, args=None):
        self.netns = netns
        if self.netns:
            self.v4 = f'10.1.1.{ns_id + 1}'
            self.v6 = f'db01::1:{ns_id + 1}'
            self.remote = f'db01::1:{2 - ns_id}'
            self.manage = self.remote
        elif args is not None:
            self.remote = args.remote
            self.manage = args.manage if args.manage else self.remote
        else:
            raise Exception('Bad config')

        self.comm_port = 16782
        self.data_port = None

        self.ynl = None
        self.verbose = None
        self.psp_dev_id = None
        self.role = None
        self.server = None
        self.comm_sock = None

    def load_args(self, ynl, args):
        self.ynl = ynl
        self.verbose = args.verbose

        if args.local or args.dev_id is None:
            devices = ynl.dev_get({}, dump=True)
            if devices is None:
                raise Exception(f"Bad PSP device count: 0 (set --local to test with nsim)")
            if len(devices) != 1:
                raise Exception(f"Bad PSP device count: {len(devices)}")
            self.psp_dev_id = devices[0]['id']
            info = devices[0]
        else:
            self.psp_dev_id = args.dev_id
            info = ynl.dev_get({"id": args.dev_id})

        # Make sure version 0 AKA hdr0-aes-gcm-128 is enabled
        if 'hdr0-aes-gcm-128' not in info['psp-versions-ena']:
            old = list(info['psp-versions-ena']) if info['psp-versions-ena'] else []
            old.append('hdr0-aes-gcm-128')
            ynl.dev_set({"id": self.psp_dev_id,
                         "psp-versions-ena": old})

    def _rendezvous_connect(self):
        try:
            s = socket.create_connection((self.manage, self.comm_port),
                                         timeout=random.uniform(0.05, 0.1))
            self.role = "client"
            self.comm_sock = s
            port = s.recv(2)
            self.data_port = struct.unpack("!H", port)[0]
            return True
        except socket.timeout:
            return False
        except TimeoutError:
            return False
        except ConnectionRefusedError:
            return False

    def rendezvous(self):
        if self._rendezvous_connect():
            return

        srv = socket.create_server(("", self.comm_port), family=socket.AF_INET6, dualstack_ipv6=True)
        while True:
            rsocks, _, _, = select.select([srv], [], [], random.uniform(0.05, 0.3))
            if rsocks:
                self.role = "server"
                self.comm_sock, _ = srv.accept()
                break
            if self._rendezvous_connect():
                break
        srv.close()

        if self.role == "server":
            self.server = socket.create_server(("", 0), family=socket.AF_INET6, dualstack_ipv6=True)
            self.data_port = self.server.getsockname()[1]
            self.comm_sock.send(struct.pack('!H', self.data_port))

    def req_echo(self, s, expect_fail=False):
        self.comm_sock.send(b'data echo\0')
        if self.comm_sock.recv(4) != b'ack\0':
            raise Exception("Unexpected server response")
        try:
            recv_careful(cfg, s, 5)
            if expect_fail:
                raise Exception("Received unexpected echo reply")
        except PSPExceptShortIO:
                if not expect_fail:
                    raise

    def make_clr_conn(self):
        self.comm_sock.send(b'conn clr\0')
        if self.comm_sock.recv(4) != b'ack\0':
            raise Exception("Unexpected server response")
        s = socket.create_connection((self.remote, self.data_port), )
        return s

    def close_conn(self, s):
        self.comm_sock.send(b'data close\0')
        if self.comm_sock.recv(4) != b'ack\0':
            raise Exception("Unexpected server response")
        s.close()

    def make_psp_conn(self):
        self.comm_sock.send(b'conn psp\0')
        if self.comm_sock.recv(4) != b'ack\0':
            raise Exception("Unexpected server response")
        s = socket.create_connection((self.remote, self.data_port), )
        return s

    def close_psp_conn(self, s):
        self.close_conn(s)

    def remote_read_len(self):
        self.comm_sock.send(b'read len\0')
        return int(self.comm_sock.recv(1024)[:-1].decode('utf-8'))


class LinkedNsimPair:
    def __init__(self):
        cfgs = [
            TestConfig(netns=NetNS(), ns_id=0),
            TestConfig(netns=NetNS(), ns_id=1)
        ]

        for cfg in cfgs:
            cfg.nsim = NetdevSimDev(ns=cfg.netns)
            cfg.ifc = cfg.nsim.nsims[0].ifname

        for cfg in cfgs:
            ip(f'link set dev {cfg.ifc} up', ns=cfg.netns)
            ip(f'a a dev {cfg.ifc} {cfg.v4}/24', ns=cfg.netns)
            ip(f'-6 a a dev {cfg.ifc} {cfg.v6}/24 nodad', ns=cfg.netns)

        with open("/var/run/netns/" + cfgs[0].netns.name) as nsfd0:
            with open("/var/run/netns/" + cfgs[1].netns.name) as nsfd1:
                ifi0 = cfgs[0].nsim.nsims[0].dev['ifindex']
                ifi1 = cfgs[1].nsim.nsims[0].dev['ifindex']
                NetdevSimDev.ctrl_write('link_device',
                                        f'{nsfd0.fileno()}:{ifi0} {nsfd1.fileno()}:{ifi1}')

        self.cfg = cfgs

    def __del__(self):
        for cfg in self.cfg:
            cfg.nsim.remove()
            del cfg.netns


def run_local(args):
    ns_pair = LinkedNsimPair()

    procs = []
    for i in range(2):
        procs.append(Process(target=local_proc, args=(ns_pair.cfg[i], args, )))
        procs[i].start()

    try:
        status = 0
        for i in range(2):
            procs[i].join()
            ret = procs[i].exitcode
            if ret > 127:
                ret = 1
            status = max(ret, status)
    finally:
        del ns_pair

    os.sys.exit(status)


def local_proc(cfg, args):
    cfg.netns.enter()
    do_work(args, cfg)


def do_work(args, _cfg):
    global cfg
    cfg = _cfg

    ynl = YnlFamily(args.spec, args.schema)
    cfg.load_args(ynl, args)
    cfg.rendezvous()
    if cfg.role == "server":
        server(cfg)
    else:
        unittest.main()
        cfg.comm_sock.close()


def main():
    other_args = []
    started = False
    for i in range(len(sys.argv)):
        if started:
            other_args.append(sys.argv[i])
        started |= sys.argv[i] == '--'
    cut = len(sys.argv) - len(other_args) - bool(other_args)
    sys.argv = sys.argv[:cut]

    parser = argparse.ArgumentParser(description='PSP functional test')
    parser.add_argument('--spec', dest='spec', type=str, default='psp.yaml')
    parser.add_argument('--schema', dest='schema', type=str, default='')
    parser.add_argument('--local', action='store_true', default=False)
    parser.add_argument('--dev-id', type=int)
    parser.add_argument('--remote', type=str, default='')
    parser.add_argument('--manage', type=str, default='',
                        help='address of remote host (if control traffic should use different address than data')
    parser.add_argument('-v', '--verbose', action='store_true', default=False)
    args = parser.parse_args()

    if bool(args.local) == bool(args.remote):
        parser.error('One of --local or --remote must be specified')
    if bool(args.local) and args.dev_id is not None:
        parser.error('Only one of --local or --dev-id can be specified')
    if args.verbose and len(other_args) == 0:
        other_args.append('-v')

    sys.argv = [sys.argv[0]] + other_args

    if args.local:
        run_local(args)
    else:
        do_work(args, TestConfig(args=args))


if __name__ == "__main__":
    main()
