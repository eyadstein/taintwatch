from taintwatch.labels import Confidentiality, Integrity, Label


def test_join_lowers_integrity_and_raises_confidentiality() -> None:
    a = Label(Integrity.USER, Confidentiality.SECRET, frozenset({"a"}))
    b = Label(Integrity.UNTRUSTED, Confidentiality.PUBLIC, frozenset({"b"}))
    joined = a.join(b)
    assert joined.integrity is Integrity.UNTRUSTED
    assert joined.confidentiality is Confidentiality.SECRET
    assert joined.sources == frozenset({"a", "b"})


def test_join_is_commutative_and_idempotent() -> None:
    a = Label(Integrity.TOOL_OUTPUT, Confidentiality.INTERNAL, frozenset({"a"}))
    b = Label(Integrity.USER, Confidentiality.PUBLIC, frozenset({"b"}))
    assert a.join(b) == b.join(a)
    assert a.join(a) == a


def test_join_all_of_nothing_is_bottom() -> None:
    assert Label.join_all([]) == Label(Integrity.SYSTEM, Confidentiality.PUBLIC)


def test_cap_integrity_only_lowers() -> None:
    high = Label(Integrity.SYSTEM)
    assert high.cap_integrity(Integrity.TOOL_OUTPUT).integrity is Integrity.TOOL_OUTPUT
    low = Label(Integrity.UNTRUSTED)
    assert low.cap_integrity(Integrity.USER).integrity is Integrity.UNTRUSTED
