from leakcheck.attack.mutate import mutate_prompt
from leakcheck.common.schemas import PromptRecord


def test_mutation_determinism():
    base = PromptRecord(id="p", category="c", text="Hello")
    ops = ["prefix_injection", "format_shift"]
    m1 = mutate_prompt(base, ops, seed=1337, idx=1)
    m2 = mutate_prompt(base, ops, seed=1337, idx=1)
    assert m1.text == m2.text
