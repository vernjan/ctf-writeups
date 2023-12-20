import logging
from dataclasses import dataclass
from typing import List, Dict

from util.data_io import read_input, read_test_input, timed_run
from util.log import log

LOW = "low"
HIGH = "high"


@dataclass(frozen=True)
class Signal:
    source_module_id: str
    module_id: str
    signal_type: str

    def __repr__(self):
        return f"{self.source_module_id} -> {self.module_id}: {self.signal_type}"


class Module:
    def __init__(self, module_id: str, output_module_ids: List[str]):
        self.module_id = module_id
        self.output_module_ids = output_module_ids

    def process_signal(self, signal: Signal) -> List[Signal]:
        return self._process_signal(signal.signal_type)

    def _process_signal(self, signal_type: str) -> List[Signal]:
        for output in self.output_module_ids:
            yield Signal(self.module_id, output, signal_type)

    def __hash__(self):
        return hash(self.module_id)

    def __eq__(self, other):
        return self.module_id == other.module_id

    def __repr__(self):
        return f"{self.module_id}"


class FlipFlop(Module):
    def __init__(self, module_id: str, output_module_ids: List[str]):
        super().__init__(module_id, output_module_ids)
        self.state = False

    def process_signal(self, signal: Signal) -> List[Signal]:
        if signal.signal_type == HIGH:
            return []
        else:
            output_signal = LOW if self.state else HIGH
            self.state = not self.state
            return super()._process_signal(output_signal)

    def __repr__(self):
        return f"%{self.module_id}: {'ON' if self.state else 'OFF'}"


class Conjunction(Module):
    def __init__(self, module_id: str, output_module_ids: List[str]):
        super().__init__(module_id, output_module_ids)
        self.memory: Dict[str, str] = {}

    def add_input_module(self, module_id: str):
        self.memory[module_id] = LOW

    def process_signal(self, signal: Signal) -> List[Signal]:
        self.memory[signal.source_module_id] = signal.signal_type
        output_signal = HIGH if LOW in self.memory.values() else LOW
        return super()._process_signal(output_signal)

    def __repr__(self):
        return f"&{self.module_id}: {self.memory}"


def star1(lines: list[str]):
    """
    >>> star1(read_test_input(__file__))
    32000000
    >>> star1(read_test_input(__file__, "input-test2.txt"))
    11687500
    """
    modules = parse_modules(lines)
    counter = {LOW: 0, HIGH: 0}
    for _ in range(1000):
        queue: List[Signal] = [Signal("button", "broadcaster", LOW)]
        while queue:
            signal = queue.pop(0)
            counter[signal.signal_type] += 1
            if signal.module_id in modules:
                module = modules[signal.module_id]
                queue.extend(module.process_signal(signal))

    log.debug(counter)
    return counter[LOW] * counter[HIGH]


def parse_modules(lines):
    modules: Dict[str, Module] = {}
    conjunction_modules: Dict[str, Conjunction] = {}
    for line in lines:
        module_id, output_module_ids = line.split(" -> ")
        assert module_id not in modules
        output_module_ids = output_module_ids.split(", ")
        if module_id.startswith("%"):
            module_id = module_id[1:]
            modules[module_id] = FlipFlop(module_id, output_module_ids)
        elif module_id.startswith("&"):
            module_id = module_id[1:]
            conjunction = Conjunction(module_id, output_module_ids)
            modules[module_id] = conjunction
            conjunction_modules[module_id] = conjunction
        else:
            modules[module_id] = Module(module_id, output_module_ids)

    for module in modules.values():
        for output in module.output_module_ids:
            if output in conjunction_modules:
                conjunction_modules[output].add_input_module(module.module_id)

    log.debug(modules)
    return modules


def star2(lines: list[str]):
    """
    >>> star2(read_test_input(__file__))

    """
    for line in lines:
        pass


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    timed_run("Star 1", lambda: star1(read_input(__file__)))
    timed_run("Star 2", lambda: star2(read_input(__file__)))

    # Star 1: 821985143
    # Star 2:
