import random
import re
from dataclasses import dataclass, field
from typing import Optional

from rsa_core import (
    generate_keypair, encrypt_text, decrypt_text,
    square_hash, verify, verify_detailed,
)
from blind_core import mask_hash, blind_sign, unblind, check_masked_hash

NUM_SETS = 10
COMMISSION_PRIME_BITS = 128
ID_LOW, ID_HIGH = 10**18, 10**19

TAMPER_KINDS = (
    "missing_ballot",
    "different_id",
    "extra_ballot",
    "extra_data",
    "duplicate_id",
    "hash_mismatch",
)


_BALLOT_RE = re.compile(r"ID=([1-9][0-9]{18}); Кандидат №([1-9][0-9]*)")


def ballot_text(ballot_id, candidate_id):
    return f"ID={ballot_id}; Кандидат №{candidate_id}"


def parse_ballot(text):
    if not isinstance(text, str):
        return None
    match = _BALLOT_RE.fullmatch(text)
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2))


SIGNATURE_SEPARATOR = " | ЕЦП ВК="


@dataclass
class BallotMessage:
    blocks: list


def build_ballot_message(text, signature, commission_public):
    return BallotMessage(
        blocks=encrypt_text(f"{text}{SIGNATURE_SEPARATOR}{signature}", commission_public)
    )


def split_message(plaintext):
    head, separator, tail = plaintext.rpartition(SIGNATURE_SEPARATOR)
    if not separator:
        return None
    if not (tail.isascii() and tail.isdigit() and len(tail) <= 100
            and (tail == "0" or tail[0] != "0")):
        return None
    return head, int(tail)


@dataclass
class BallotSet:
    index: int
    ballot_id: int
    ballots: list
    masked: list


@dataclass
class RevealedSet:
    ballots: list
    multipliers: list


@dataclass
class PublishedEntry:
    ballot_id: int
    text: str
    signature: int


class Voter:
    def __init__(self, full_name, candidate_ids, rng=None):
        self.full_name = full_name
        self.candidate_ids = list(candidate_ids)
        self.rng = rng or random.SystemRandom()
        self.sets = []
        self.unopened_index = None
        self.signed = []
        self.cast_log = []

    def _new_id(self, used):
        while True:
            value = self.rng.randrange(ID_LOW, ID_HIGH)
            if value not in used:
                return value

    def prepare_sets(self, commission_public, tamper=None):
        n = commission_public[1]
        tamper = tamper or {}
        ids = []
        for _ in range(NUM_SETS):
            ids.append(self._new_id(ids))

        self.sets = []
        for i in range(NUM_SETS):
            set_id = ids[i]
            kind = tamper.get(i)
            if kind is not None and kind not in TAMPER_KINDS:
                raise ValueError(f"невідомий вид порушення: {kind}")
            if kind == "duplicate_id":
                set_id = ids[(i + 1) % NUM_SETS]

            ballots = [ballot_text(set_id, c) for c in self.candidate_ids]
            hashed = list(ballots)
            if kind == "missing_ballot":
                ballots = ballots[:-1]
                hashed = list(ballots)
            elif kind == "different_id":
                ballots[-1] = ballot_text(self._new_id(ids), self.candidate_ids[-1])
                hashed = list(ballots)
            elif kind == "extra_ballot":
                ballots.append(ballot_text(set_id, max(self.candidate_ids) + 1))
                hashed = list(ballots)
            elif kind == "extra_data":
                ballots[-1] += "; бонус"
                hashed = list(ballots)
            elif kind == "hash_mismatch":
                hashed[-1] = ballot_text(set_id + 1, self.candidate_ids[-1])

            masked = [mask_hash(square_hash(t, n), commission_public, self.rng)
                      for t in hashed]
            self.sets.append(BallotSet(i, set_id, ballots, masked))
        return self.masked_sets()

    def masked_sets(self):
        return [[m.h_masked for m in s.masked] for s in self.sets]

    def reveal(self, indices):
        indices = sorted(set(indices))
        revealed = {
            i: RevealedSet(ballots=list(self.sets[i].ballots),
                           multipliers=[m.r for m in self.sets[i].masked])
            for i in indices
        }
        rest = [i for i in range(NUM_SETS) if i not in indices]
        self.unopened_index = rest[0] if len(rest) == 1 else None
        return revealed

    def receive_signatures(self, blind_signatures, commission_public):
        if self.unopened_index is None:
            raise ValueError("немає єдиного нерозкритого набору")
        chosen = self.sets[self.unopened_index]
        if len(blind_signatures) != len(chosen.masked):
            raise ValueError("кількість підписів не збігається з кількістю бюлетенів")
        n = commission_public[1]
        self.signed = []
        all_valid = True
        for text, item, s_masked in zip(chosen.ballots, chosen.masked, blind_signatures):
            signature = unblind(s_masked, item.r, n)
            all_valid = all_valid and verify(text, signature, commission_public)
            self.signed.append((text, signature))
        return all_valid

    def cast_signed(self, position, commission_public):
        text, signature = self.signed[position]
        parsed = parse_ballot(text)
        self.cast_log.append((parsed[0] if parsed else None, text, signature))
        return build_ballot_message(text, signature, commission_public)

    def cast(self, candidate_id, commission_public):
        for position, (text, _) in enumerate(self.signed):
            parsed = parse_ballot(text)
            if parsed is not None and parsed[1] == candidate_id:
                return self.cast_signed(position, commission_public)
        raise ValueError(f"у підписаному наборі немає бюлетеня за кандидата №{candidate_id}")

    def verify_in_published(self, published):
        by_id = {entry.ballot_id: entry for entry in published}
        result = []
        for ballot_id, text, signature in self.cast_log:
            entry = by_id.get(ballot_id)
            same = entry is not None and entry.text == text and entry.signature == signature
            result.append((ballot_id, entry is not None, same))
        return result


@dataclass
class RequestReport:
    voter_name: str
    in_list: Optional[bool] = None
    not_received_before: Optional[bool] = None
    sets_ok: Optional[bool] = None
    accepted: bool = False
    reason: str = ""


@dataclass
class SetCheck:
    index: int
    ballot_id: Optional[int] = None
    n_ballots: int = 0
    hash_checks: list = field(default_factory=list)
    problems: list = field(default_factory=list)

    @property
    def number(self):
        return self.index + 1

    @property
    def ok(self):
        return not self.problems


@dataclass
class RevealReport:
    voter_name: str
    requested: list
    unopened_index: Optional[int] = None
    set_checks: list = field(default_factory=list)
    problems: list = field(default_factory=list)
    ok: bool = False
    signatures: Optional[list] = None
    reason: str = ""


@dataclass
class BallotReport:
    decrypt_ok: bool = False
    text: Optional[str] = None
    signature: Optional[int] = None
    format_ok: Optional[bool] = None
    ballot_id: Optional[int] = None
    candidate_id: Optional[int] = None
    hash_from_text: Optional[int] = None
    hash_from_signature: Optional[int] = None
    signature_ok: Optional[bool] = None
    id_unique: Optional[bool] = None
    accepted: bool = False
    reason: str = ""


@dataclass
class ElectionResult:
    counts: dict
    spoiled: int
    valid_total: int
    accepted_total: int
    rejected_total: int
    status: str
    leaders: list


@dataclass
class _Session:
    masked_sets: list
    revealed: Optional[list] = None
    unopened: Optional[int] = None


class ElectionCommission:
    def __init__(self, candidates, rng=None):
        self.candidates = dict(candidates)
        self.keys = generate_keypair(COMMISSION_PRIME_BITS, rng)
        self.voter_list = []
        self.signed_registry = {}
        self.accepted = {}
        self.rejected_total = 0
        self._sessions = {}

    @property
    def public_key(self):
        return self.keys.public

    def register_voter(self, full_name):
        if full_name in self.signed_registry:
            raise ValueError(f"виборець вже є у списку: {full_name}")
        self.voter_list.append(full_name)
        self.signed_registry[full_name] = False


    def receive_masked_sets(self, voter_name, masked_sets):
        report = RequestReport(voter_name=voter_name)

        def refuse(reason):
            report.accepted = False
            report.reason = reason
            return report

        report.in_list = voter_name in self.signed_registry
        if not report.in_list:
            return refuse("виборця немає у списку виборців")

        report.not_received_before = not self.signed_registry[voter_name]
        if not report.not_received_before:
            return refuse("виборець вже отримував підписаний набір бюлетенів")

        n = self.keys.n
        report.sets_ok = (
            len(masked_sets) == NUM_SETS
            and all(len(s) > 0 and all(isinstance(x, int) and 0 <= x < n for x in s)
                    for s in masked_sets)
        )
        if not report.sets_ok:
            return refuse(f"має бути {NUM_SETS} наборів коректних замаскованих хешів")

        self._sessions[voter_name] = _Session(masked_sets=[list(s) for s in masked_sets])
        report.accepted = True
        report.reason = f"запит прийнято: отримано {NUM_SETS} наборів замаскованих хешів"
        return report


    def choose_sets_to_reveal(self, voter_name, rng=None, unopened=None):
        session = self._sessions.get(voter_name)
        if session is None:
            raise ValueError("немає активного запиту цього виборця")
        rng = rng or random.SystemRandom()
        if unopened is None:
            unopened = rng.randrange(NUM_SETS)
        session.unopened = unopened
        session.revealed = [i for i in range(NUM_SETS) if i != unopened]
        return list(session.revealed)


    def _check_set(self, index, revealed_set, masked):
        n = self.keys.n
        ballots = revealed_set.ballots
        check = SetCheck(index=index, n_ballots=len(ballots))
        problems = check.problems

        if len(ballots) != len(revealed_set.multipliers):
            problems.append("кількість множників не збігається з кількістю бюлетенів")
        if len(ballots) != len(masked):
            problems.append("кількість розкритих бюлетенів не збігається з кількістю "
                            "отриманих замаскованих хешів")

        parsed = [parse_ballot(t) for t in ballots]
        for k, p in enumerate(parsed):
            if p is None:
                problems.append(f"бюлетень №{k + 1} має некоректний формат (зайві дані)")

        candidates = [p[1] for p in parsed if p is not None]
        missing = [c for c in sorted(self.candidates) if c not in candidates]
        extra = sorted({c for c in candidates if c not in self.candidates})
        duplicates = sorted({c for c in candidates if candidates.count(c) > 1})
        if missing:
            problems.append("відсутні бюлетені для кандидатів: "
                            + ", ".join(f"№{c}" for c in missing))
        if extra:
            problems.append("зайві бюлетені (кандидатів не існує): "
                            + ", ".join(f"№{c}" for c in extra))
        if duplicates:
            problems.append("повторні бюлетені для кандидатів: "
                            + ", ".join(f"№{c}" for c in duplicates))

        ids = {p[0] for p in parsed if p is not None}
        if len(ids) > 1:
            problems.append("бюлетені набору мають різні ID")
        elif len(ids) == 1:
            check.ballot_id = next(iter(ids))

        for k in range(min(len(ballots), len(revealed_set.multipliers), len(masked))):
            text = ballots[k]
            ok = isinstance(text, str) and check_masked_hash(
                square_hash(text, n), revealed_set.multipliers[k], masked[k], self.public_key)
            check.hash_checks.append(ok)
            if not ok:
                problems.append(f"бюлетень №{k + 1}: хеш не відповідає замаскованому "
                                f"хешу (H·r^e mod n ≠ H')")
        return check

    def process_reveal(self, voter_name, revealed):
        session = self._sessions.pop(voter_name, None)
        report = RevealReport(
            voter_name=voter_name,
            requested=list(session.revealed) if session and session.revealed else [],
        )
        if session is None or session.unopened is None:
            report.problems.append("немає активного запиту або набори для розкриття не вибрано")
            report.reason = "підписання відмовлено"
            return report
        report.unopened_index = session.unopened

        expected, got = set(session.revealed), set(revealed)
        if got != expected:
            extra = sorted(got - expected)
            missing = sorted(expected - got)
            if extra:
                report.problems.append("розкрито набори, які не запитувались: "
                                       + ", ".join(f"№{i + 1}" for i in extra))
            if missing:
                report.problems.append("не розкрито запитані набори: "
                                       + ", ".join(f"№{i + 1}" for i in missing))
            report.reason = "підписання відмовлено"
            return report

        for i in sorted(expected):
            report.set_checks.append(self._check_set(i, revealed[i], session.masked_sets[i]))

        seen = {}
        for check in report.set_checks:
            if check.ballot_id is None:
                continue
            if check.ballot_id in seen:
                report.problems.append(
                    f"однаковий ID у наборах №{seen[check.ballot_id] + 1} та №{check.number}")
            else:
                seen[check.ballot_id] = check.index

        report.ok = not report.problems and all(c.ok for c in report.set_checks)
        if not report.ok:
            report.reason = "виявлено некоректний набір: підписання відмовлено"
            return report

        report.signatures = [blind_sign(h, self.keys.private)
                             for h in session.masked_sets[session.unopened]]
        self.signed_registry[voter_name] = True
        report.reason = "усі розкриті набори коректні: нерозкритий набір підписано"
        return report


    def _reject_ballot(self, report, reason):
        report.accepted = False
        report.reason = reason
        self.rejected_total += 1
        return report

    def receive_ballot(self, message):
        report = BallotReport()

        try:
            plaintext = decrypt_text(message.blocks, self.keys.private)
            plaintext.encode("utf-8")
        except ValueError:
            return self._reject_ballot(report, "не вдалося розшифрувати повідомлення")
        report.decrypt_ok = True

        parts = split_message(plaintext)
        parsed = parse_ballot(parts[0]) if parts is not None else None
        report.format_ok = parsed is not None
        if parsed is None:
            report.text = plaintext
            return self._reject_ballot(report, "некоректний формат повідомлення або бюлетеня")
        text, signature = parts
        report.text, report.signature = text, signature
        report.ballot_id, report.candidate_id = parsed

        h, hc, ok = verify_detailed(text, signature, self.public_key)
        report.hash_from_text = h
        report.hash_from_signature = hc
        report.signature_ok = ok
        if not ok:
            return self._reject_ballot(report, "ЕЦП ВК недійсний (H ≠ Hc)")

        report.id_unique = report.ballot_id not in self.accepted
        if not report.id_unique:
            return self._reject_ballot(report, "ID вже використовувався")

        self.accepted[report.ballot_id] = (text, signature, report.candidate_id)
        report.accepted = True
        report.reason = "ЕЦП дійсний, ID унікальний"
        return report


    def tally(self):
        counts = {candidate_id: 0 for candidate_id in self.candidates}
        spoiled = 0
        for _, _, candidate_id in self.accepted.values():
            if candidate_id in counts:
                counts[candidate_id] += 1
            else:
                spoiled += 1

        valid_total = sum(counts.values())
        top = max(counts.values()) if counts else 0
        leaders = [cid for cid, c in counts.items() if c == top]
        if valid_total == 0:
            status, leaders = "no_votes", []
        elif len(leaders) > 1:
            status = "tie"
        else:
            status = "winner"

        return ElectionResult(
            counts=counts,
            spoiled=spoiled,
            valid_total=valid_total,
            accepted_total=len(self.accepted),
            rejected_total=self.rejected_total,
            status=status,
            leaders=leaders,
        )

    def publish(self):
        return [PublishedEntry(ballot_id=i, text=text, signature=signature)
                for i, (text, signature, _) in sorted(self.accepted.items())]


def verify_published(entries, commission_public):
    ids = [entry.ballot_id for entry in entries]
    if len(set(ids)) != len(ids):
        return False
    for entry in entries:
        parsed = parse_ballot(entry.text)
        if parsed is None or parsed[0] != entry.ballot_id:
            return False
        if not verify(entry.text, entry.signature, commission_public):
            return False
    return True


@dataclass
class IssuanceResult:
    request: RequestReport
    indices: Optional[list] = None
    reveal: Optional[RevealReport] = None
    signatures_ok: Optional[bool] = None

    @property
    def signed(self):
        return self.reveal is not None and self.reveal.ok


def issue_signed_set(commission, voter, rng=None, tamper=None, unopened=None):
    masked = voter.prepare_sets(commission.public_key, tamper)
    request = commission.receive_masked_sets(voter.full_name, masked)
    result = IssuanceResult(request=request)
    if not request.accepted:
        return result
    result.indices = commission.choose_sets_to_reveal(voter.full_name, rng, unopened)
    revealed = voter.reveal(result.indices)
    result.reveal = commission.process_reveal(voter.full_name, revealed)
    if result.reveal.ok:
        result.signatures_ok = voter.receive_signatures(
            result.reveal.signatures, commission.public_key)
    return result
