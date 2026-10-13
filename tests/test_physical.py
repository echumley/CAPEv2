import importlib
import json
from types import SimpleNamespace

import pytest
import requests
from pytest_mock import MockerFixture

from lib.cuckoo.common.exceptions import CuckooMachineError

FOG = "fog.example"
LINUX = SimpleNamespace(label="bm-linux", name="bm-linux", ip="192.168.102.11", platform="linux")
WINDOWS = SimpleNamespace(label="bm-win10", name="bm-win10", ip="192.168.102.12", platform="windows")
UNKNOWN = SimpleNamespace(label="bm-ghost", name="bm-ghost", ip="192.168.102.13", platform="linux")
FOG_HOSTS = {
    "hosts": [
        {"id": 7, "name": "bm-linux", "macs": ["aa:bb:cc:dd:ee:01"]},
        {"id": 8, "name": "bm-win10", "macs": ["aa:bb:cc:dd:ee:02"]},
    ]
}
FOG_TASK_TYPES = {"tasktypes": [{"id": 2, "name": "Capture"}, {"id": 1, "name": "Deploy"}]}

class FakeClock:
    """Deterministic clock for the restore timeout."""

    def __init__(self):
        self.now = 0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds

class FakeNetwork:
    """FOG's API and the machines' agents, as seen through requests.get/post."""

    def __init__(self, agent, active_polls=1, deploy_status=200):
        # One entry per agent /status call: True answers, False is unreachable.
        # The last entry repeats once the list is used up.
        self.agent = list(agent)
        # How many /fog/task/active polls still list the restore task.
        self.active_polls = active_polls
        self.deploy_status = deploy_status
        self.deploys = []
        self.executes = []

    def get(self, url, **kwargs):
        assert kwargs.get("timeout"), f"GET {url} has no timeout"
        if url == f"http://{FOG}/fog/host":
            return response(FOG_HOSTS)
        if url == f"http://{FOG}/fog/tasktype":
            return response(FOG_TASK_TYPES)
        if url == f"http://{FOG}/fog/task/active":
            if self.active_polls > 0:
                self.active_polls -= 1
                return response({"tasks": [{"host": {"id": 7}}, {"host": {"id": 8}}]})
            return response({"tasks": []})
        if url.endswith(":8000/status"):
            up = self.agent.pop(0) if len(self.agent) > 1 else self.agent[0]
            if not up:
                raise requests.exceptions.ConnectionError(url)
            return response({"status": "init"})
        raise AssertionError(f"unexpected GET {url}")

    def post(self, url, **kwargs):
        assert kwargs.get("timeout"), f"POST {url} has no timeout"
        if url.startswith(f"http://{FOG}/fog/host/") and url.endswith("/task"):
            self.deploys.append((int(url.split("/")[-2]), json.loads(kwargs["data"])))
            return response({}, self.deploy_status)
        if url.endswith(":8000/execute"):
            self.executes.append((url.split("//")[1].split(":")[0], kwargs["data"]))
            return response({"message": "Successfully executed command"})
        raise AssertionError(f"unexpected POST {url}")

def response(data, status_code=200):
    return SimpleNamespace(ok=status_code < 400, status_code=status_code, text=json.dumps(data), json=lambda: data)

@pytest.fixture
def physical_module(monkeypatch: pytest.MonkeyPatch):
    module = importlib.import_module("modules.machinery.physical")
    monkeypatch.setattr(module, "managerType", "pure")
    # Normally set by _initialize_check().
    monkeypatch.setattr(module, "headers", {"fog-api-token": "a", "fog-user-token": "b"}, raising=False)
    return module

def make_machinery(physical_module, restore_timeout=600):
    machinery = physical_module.Physical.__new__(physical_module.Physical)
    machinery.options = SimpleNamespace(
        physical=SimpleNamespace(type="pure", restore_timeout=restore_timeout),
        fog=SimpleNamespace(hostname=FOG, apikey="a", user_apikey="b"),
    )
    machinery.machines = lambda: [LINUX, WINDOWS, UNKNOWN]
    return machinery

def install(physical_module, mocker: MockerFixture, network):
    clock = FakeClock()
    mocker.patch.object(physical_module.time, "monotonic", clock.monotonic)
    mocker.patch.object(physical_module.time, "sleep", clock.sleep)
    mocker.patch.object(physical_module.requests, "get", side_effect=network.get)
    mocker.patch.object(physical_module.requests, "post", side_effect=network.post)
    return clock

DEPLOY = {"taskTypeID": 1, "shutdown": "", "wol": "true"}

def test_stop_reboots_linux_machines_with_reboot(physical_module, mocker: MockerFixture):
    network = FakeNetwork(agent=[True, False, True])
    install(physical_module, mocker, network)

    make_machinery(physical_module).stop("bm-linux")

    assert network.deploys == [(7, DEPLOY)]
    assert network.executes == [("192.168.102.11", {"command": "reboot -f", "async": "1"})]

def test_stop_keeps_the_windows_shutdown_command(physical_module, mocker: MockerFixture):
    network = FakeNetwork(agent=[True, True])
    install(physical_module, mocker, network)

    make_machinery(physical_module).stop("bm-win10")

    assert network.deploys == [(8, DEPLOY)]
    assert network.executes == [("192.168.102.12", {"command": "shutdown -r -f -t 0"})]

def test_stop_gives_up_when_fog_never_finishes(physical_module, mocker: MockerFixture):
    network = FakeNetwork(agent=[True], active_polls=10**6)
    clock = install(physical_module, mocker, network)

    with pytest.raises(CuckooMachineError, match="FOG did not restore physical machine bm-linux within 600 seconds"):
        make_machinery(physical_module).stop("bm-linux")
    assert 600 <= clock.now < 620

def test_stop_gives_up_when_the_machine_never_comes_back(physical_module, mocker: MockerFixture):
    network = FakeNetwork(agent=[True, False])
    clock = install(physical_module, mocker, network)

    with pytest.raises(CuckooMachineError, match="bm-linux did not come back within 600 seconds"):
        make_machinery(physical_module).stop("bm-linux")
    assert 600 <= clock.now < 610

def test_stop_does_not_reboot_when_fog_refuses_the_restore(physical_module, mocker: MockerFixture):
    network = FakeNetwork(agent=[True], deploy_status=500)
    install(physical_module, mocker, network)

    with pytest.raises(CuckooMachineError, match="FOG refused to restore host 7: 500"):
        make_machinery(physical_module).stop("bm-linux")
    assert network.executes == []

def test_stop_restores_a_machine_whose_agent_is_gone(physical_module, mocker: MockerFixture):
    network = FakeNetwork(agent=[False, True])
    install(physical_module, mocker, network)
    machinery = make_machinery(physical_module)
    wake = mocker.patch.object(machinery, "wake_on_lan")

    machinery.stop("bm-linux")

    assert network.deploys == [(7, DEPLOY)]
    assert network.executes == []
    wake.assert_called_once_with("bm-linux")

def test_stop_rejects_machines_missing_from_fog(physical_module, mocker: MockerFixture):
    network = FakeNetwork(agent=[True])
    install(physical_module, mocker, network)

    with pytest.raises(CuckooMachineError, match="bm-ghost has not been defined in FOG"):
        make_machinery(physical_module).stop("bm-ghost")
    assert network.deploys == []

def test_wake_on_lan_sends_the_magic_packet(physical_module, mocker: MockerFixture):
    install(physical_module, mocker, FakeNetwork(agent=[True]))
    sock = mocker.patch.object(physical_module.socket, "socket").return_value

    make_machinery(physical_module).wake_on_lan("bm-linux")

    packet, address = sock.sendto.call_args.args
    assert packet == b"\xff" * 6 + bytes.fromhex("aabbccddee01") * 16
    assert address == ("192.168.102.255", 54545)

def test_wake_on_lan_ignores_machines_missing_from_fog(physical_module, mocker: MockerFixture):
    install(physical_module, mocker, FakeNetwork(agent=[True]))
    sock = mocker.patch.object(physical_module.socket, "socket")

    make_machinery(physical_module).wake_on_lan("bm-ghost")

    sock.assert_not_called()
