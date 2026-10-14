# Copyright (C) 2012-2014 The MITRE Corporation.
# Copyright (C) 2015-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import socket
import struct
import sys
import time

import requests

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_GUEST_PORT
from lib.cuckoo.common.exceptions import CuckooCriticalError, CuckooMachineError

log = logging.getLogger(__name__)
managerType = Config("physical").physical.type

if managerType == "proxmox":
    from lib.cuckoo.common.hypervisor_config import proxmox_shutdown_vm

# Seconds allowed for one HTTP request to FOG or to a machine's agent.
HTTP_TIMEOUT = 10
# Default for [physical] restore_timeout: seconds for a FOG restore plus the
# reboot into the restored system before the machine is reported as broken.
RESTORE_TIMEOUT = 1800

class Physical(Machinery):
    """Manage physical sandboxes."""

    module_name = "physical"

    # Physical machine states.
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"

    headers = {}

    def __init__(self):
        super().__init__()
        # Machines whose FOG restore has not completed since their last analysis.
        self.unrestored = set()

    def _initialize_check(self):
        """Ensure that credentials have been entered into the config file.
        @raise CuckooCriticalError: if no credentials were provided or if
            one or more physical machines are offline.
        """
        # TODO This should be moved to a per-machine thing.
        global headers
        headers = {
            "fog-api-token": self.options.fog.apikey,
            "fog-user-token": self.options.fog.user_apikey,
            "Content-Type": "application/json",
        }

        self.fog_init()

        for machine in self.machines():
            status = self._status(machine.label)
            if status == self.STOPPED:
                # Send a Wake On Lan message (if we're using FOG).
                self.wake_on_lan(machine.label)
            elif status == self.ERROR:
                raise CuckooMachineError(
                    "Unknown error occurred trying to obtain the status of "
                    f"physical machine {machine.label}. Please turn it on "
                    " and check the Cuckoo Agent"
                )

    def _get_machine(self, label):
        """Retrieve all machine info given a machine's name.
        @param label: machine name.
        @return: machine dictionary (id, ip, platform, ...).
        @raises CuckooMachineError: if no machine is available with the given label.
        """
        for m in self.machines():
            if label == m.label:
                return m

        raise CuckooMachineError(f"No machine with label: {label}")

    def isTaskigDone(self, hostID):
        """This function checks if there are any running tasks for host ID in fog
        @param hostID: ID of the host to look for tasks
        @return: Returns true if there is an active task and false if there are none
        """
        try:
            searchURL = f"http://{self.options.fog.hostname}/fog/task/active"
            r = requests.get(searchURL, headers=headers, timeout=HTTP_TIMEOUT)
            tasks = r.json()["tasks"]
            return all(task["host"]["id"] != hostID for task in tasks)
        except Exception:
            raise CuckooMachineError(f"Error while checking for fog task state for hostID {hostID}: {sys.exc_info()[0]}")

    def start(self, label):
        """Start a physical machine.
        @param label: physical machine name.
        @param task: task object.
        @raise CuckooMachineError: if unable to start, or if the machine has not
            been restored since its last analysis.
        """
        # CAPE releases a machine even when stop() fails, and running the next
        # sample on the previous one's system would taint both reports.
        if label in self.unrestored:
            raise CuckooMachineError(
                f"Physical machine {label} has not been restored since its last analysis. "
                "Check its FOG restore, then restart CAPE to use it again"
            )

        # Check to ensure a given machine is running
        log.debug("Checking if machine %s is running", label)
        status = self._status(label)
        if status == self.RUNNING:
            log.debug("Machine already running: %s", label)
        elif status == self.STOPPED:
            self._wait_status(label, self.RUNNING)
        else:
            raise CuckooMachineError(f"Error occurred while starting: {label} (STATUS={status})")

    def stop(self, label):
        """Restore a physical machine with FOG and wait until it is back.
        @param label: physical machine name.
        @raise CuckooMachineError: if FOG cannot restore the machine, or it does
            not come back within [physical] restore_timeout seconds. start()
            then refuses the machine.
        """
        machine = self._get_machine(label)
        self.unrestored.add(label)
        hostID = self._fog_host_id(label)

        # Deploy Task to reset physical machine to former state. FOG runs it on the
        # next network boot, so it is queued even when the agent no longer answers.
        self._queue_deploy(hostID)

        if self._status(label) == self.RUNNING:
            log.debug("Rebooting machine: %s", label)
            try:
                self._reboot(machine)
            except requests.exceptions.RequestException:
                # The reboot will start immediately which may kill our socket so we just ignore this exception
                log.debug("Socket killed from analysis machine due to reboot")
        else:
            # The sample may have powered the machine off. One that hangs still
            # needs a manual power cycle.
            log.warning("Agent on %s does not answer, sending Wake on Lan for its FOG restore", label)
            self.wake_on_lan(label)

        timeout = int(getattr(self.options.physical, "restore_timeout", None) or RESTORE_TIMEOUT)
        deadline = time.monotonic() + timeout

        # We are waiting until we are able to connect to the agent again since we dont know how long it will take to restore the machine
        while not self.isTaskigDone(hostID):
            if time.monotonic() >= deadline:
                raise CuckooMachineError(f"FOG did not restore physical machine {label} within {timeout} seconds")
            log.debug("Restore operation for %s still running", label)
            time.sleep(10)

        # After the restore operation is done we are waiting until it is up again and we can connect to the agent
        while self._status(label) != self.RUNNING:
            if time.monotonic() >= deadline:
                raise CuckooMachineError(f"Physical machine {label} did not come back within {timeout} seconds of its FOG restore")
            log.debug("Machine not reachable yet after reset")
            time.sleep(3)

        self.unrestored.discard(label)

    def _fog_host_id(self, label):
        """Return FOG's ID for a machine; FOG host names are the machine labels."""
        r_hosts = requests.get(f"http://{self.options.fog.hostname}/fog/host", headers=headers, timeout=HTTP_TIMEOUT)
        for host in r_hosts.json()["hosts"]:
            if host["name"] == label:
                return host["id"]
        raise CuckooMachineError(f"The physical machine {label} has not been defined in FOG")

    def _queue_deploy(self, hostID):
        """Queue FOG's Deploy task, which restores the machine's image on its next network boot."""
        r_types = requests.get(f"http://{self.options.fog.hostname}/fog/tasktype", headers=headers, timeout=HTTP_TIMEOUT)
        taskID_Deploy = next((t["id"] for t in r_types.json()["tasktypes"] if t["name"] == "Deploy"), 0)
        payload = json.dumps({"taskTypeID": taskID_Deploy, "shutdown": "", "wol": "true"}).encode()
        r = requests.post(
            f"http://{self.options.fog.hostname}/fog/host/{hostID}/task", headers=headers, data=payload, timeout=HTTP_TIMEOUT
        )
        if not r.ok:
            # Carrying on would run the next analysis on the dirty system.
            raise CuckooMachineError(f"FOG refused to restore host {hostID}: {r.status_code} {r.text[:200]}")

    def _reboot(self, machine):
        """Reboot a machine so that it network-boots into its FOG restore."""
        if managerType == "proxmox":
            proxmox_shutdown_vm(machine.name)
        elif managerType == "pure":
            if machine.platform == "linux":
                # Linux has no "shutdown -f"; reboot in the background so the agent still answers.
                data = {"command": "reboot -f", "async": "1"}
            else:
                data = {"command": "shutdown -r -f -t 0"}
            requests.post(f"http://{machine.ip}:{CUCKOO_GUEST_PORT}/execute", data=data, timeout=HTTP_TIMEOUT)

    def _list(self):
        """List physical machines installed.
        @return: physical machine names list.
        """
        return [machine.label for machine in self.machines() if self._status(machine.label) == self.RUNNING]

    def _status(self, label):
        """Get current status of a physical machine.
        @param label: physical machine name.
        @return: status string.
        """
        # For physical machines, the agent can either be contacted or not.
        # However, there is some information to be garnered from potential
        # exceptions.
        log.debug("Getting status for machine: %s", label)
        machine = self._get_machine(label)

        # The status is only used to determine whether the Guest is running
        # or whether it is in a stopped status, therefore the timeout can most
        # likely be fairly arbitrary. TODO This is a temporary fix as it is
        # not compatible with the new Cuckoo Agent, but it will have to do.
        url = f"http://{machine.ip}:{CUCKOO_GUEST_PORT}"

        try:
            r = requests.get(f"{url}/status", timeout=HTTP_TIMEOUT)
            log.debug("Agent on %s answered: %s", label, r.text)
            return self.RUNNING
        except Exception:
            return self.STOPPED

    def fog_init(self):
        """Initiate by indexing FOG regarding all available machines."""
        self.fog_machines = {}
        if self.options.fog.hostname == "none":
            return

        # TODO Handle exceptions such as not being able to connect.

        # Parse the HTML.
        r = requests.get(f"http://{self.options.fog.hostname}/fog/status", headers=headers, verify=False, timeout=HTTP_TIMEOUT)

        if r.status_code != 200:
            raise CuckooCriticalError(f"The FOG server answered with the status code {r.status_code}")

        r_hosts = requests.get(f"http://{self.options.fog.hostname}/fog/host", headers=headers, verify=False, timeout=HTTP_TIMEOUT)
        hosts = r_hosts.json()["hosts"]
        hostnames = []
        for host in hosts:
            hostnames.append(host["name"])
            log.debug("Host %s has MAC %s", host["name"], host["macs"][0])

            # Check whether all our machines are available on FOG.
        for machine in self.machines():
            if machine.label not in hostnames:
                raise CuckooMachineError(
                    f"The physical machine {machine.label} has not been defined in FOG, "
                    "please investigate and configure the configuration correctly"
                )

    def fog_queue_task(self, hostname):
        """Queue a task with FOG to deploy the given machine after reboot."""
        if hostname in self.fog_machines:
            macaddr, download = self.fog_machines[hostname]
            self.fog_query(download)

    def wake_on_lan(self, label):
        """Start a machine that's currently shutdown."""
        machine = self._get_machine(label)

        r_hosts = requests.get(f"http://{self.options.fog.hostname}/fog/host", headers=headers, verify=False, timeout=HTTP_TIMEOUT)
        hosts = r_hosts.json()["hosts"]
        macaddr = ""
        for host in hosts:
            if label == host["name"]:
                macaddr = host["macs"][0]

        ip = machine.ip
        parts = ip.split(".")
        broadcastip = f"{'.'.join(parts[:3])}.255"

        if len(macaddr) == 0:
            log.debug("No Machine with hostname %s found", label)
            return

        packet = self.create_magic_packet(macaddr)
        if not packet:
            log.debug("Sending Wake on Lan message has failed")
            return

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        log.debug("Sending Wake on Lan message for %s (%s) to Broadcast IP %s", label, macaddr, broadcastip)
        sock.sendto(packet, (broadcastip, 54545))
        sock.close()

    def create_magic_packet(self, macaddress):
        if len(macaddress) == 12:
            pass
        elif len(macaddress) == 17:
            sep = macaddress[2]
            macaddress = macaddress.replace(sep, "")
        else:
            log.debug("Incorrect MAC address format: %s", macaddress)
            return False

        # Pad the synchronization stream
        data = b"FFFFFFFFFFFF" + (macaddress * 16).encode()
        send_data = b""

        # Split up the hex values in pack
        for i in range(0, len(data), 2):
            send_data += struct.pack(b"B", int(data[i : i + 2], 16))
        return send_data
