from leakcheck.common.schemas import PromptRecord

def test_prompt_record():
    p = PromptRecord(id="1", category="x", text="hi")
    assert p.id == "1"
