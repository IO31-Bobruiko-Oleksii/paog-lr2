import argparse
import random
import sys
from dataclasses import replace

from rsa_core import square_hash, mod_inverse
from blind_core import blind
from blind_voting import (
    NUM_SETS, ElectionCommission, Voter,
    ballot_text, parse_ballot, build_ballot_message, SIGNATURE_SEPARATOR,
    verify_published, issue_signed_set,
)

try:
    sys.stdout.reconfigure(encoding="utf-8")
except AttributeError:
    pass

CANDIDATES = {
    1: "Іваненко Тарас Олексійович",
    2: "Мороз Ірина Степанівна",
}

VOTER_NAMES = [
    "Коваленко Олександр Іванович",
    "Шевченко Марія Петрівна",
    "Бондаренко Андрій Сергійович",
    "Ткаченко Оксана Миколаївна",
    "Мельник Дмитро Васильович",
]

OUTSIDER_NAME = "Савчук Ігор Олегович"
SNEAKY_NAME = "Гриценко Віктор Павлович"

SUMMARY = []
VIEW = {}
_counter = [0]


def header(text):
    print("\n" + "=" * 78)
    print(text)
    print("=" * 78)


def scenario(title, note=None):
    _counter[0] += 1
    print(f"\n--- {_counter[0]}. {title} ---")
    if note:
        print(f"Пояснення: {note}")
    return _counter[0]


def record(number, title, expected, got, ok=None):
    SUMMARY.append((number, title, expected, got, (expected == got) if ok is None else ok))


def yes_no(value):
    if value is None:
        return "не перевірялась"
    return "ТАК" if value else "НІ"


def plural(n, one, few, many):
    last, last_two = n % 10, n % 100
    if last == 1 and last_two != 11:
        return one
    if 2 <= last <= 4 and not 12 <= last_two <= 14:
        return few
    return many


def percent(value):
    return f"{100 * value:.1f}".replace(".", ",") + " %"


def short(number, width=22):
    text = str(number)
    if len(text) <= width:
        return text
    head = (width - 1) // 2 + 1
    tail = width - 1 - head
    return text[:head] + "…" + text[-tail:]


def blocks_short(blocks, shown=2):
    head = ", ".join(short(b, 16) for b in blocks[:shown])
    count = len(blocks)
    word = plural(count, "блок", "блоки", "блоків")
    return f"[{head}, …, {short(blocks[-1], 16)}] ({count} {word})"


def numbers(items):
    return ", ".join(f"№{i}" for i in items)


def show_keypair(label, kp):
    print(f"\n  {label}")
    print(f"    p      = {kp.p}")
    print(f"    q      = {kp.q}")
    print(f"    n      = p·q = {kp.n}")
    print(f"    φ(n)   = (p-1)(q-1) = {kp.phi}")
    print(f"    e      = {kp.e}")
    print(f"    d      = {kp.d}")
    print(f"    перевірка: (e·d) mod φ(n) = {(kp.e * kp.d) % kp.phi}")


TAMPER_TEXT = {
    "missing_ballot": "у наборі №{k} немає бюлетеня для кандидата №2",
    "different_id": "у наборі №{k} бюлетень для кандидата №2 має інший ID, ніж бюлетень для кандидата №1",
    "extra_ballot": "у наборі №{k} є зайвий бюлетень («Кандидат №3», такого кандидата немає)",
    "extra_data": "у тексті одного з бюлетенів набору №{k} є зайві дані",
    "duplicate_id": "ID набору №{k} збігається з ID набору №{kk}",
    "hash_mismatch": "замаскований хеш одного з бюлетенів набору №{k} обчислено не від того бюлетеня, "
                     "який буде розкрито",
}


TAMPER_NAME = {
    "missing_ballot": "бракує бюлетеня",
    "different_id": "різні ID у наборі",
    "extra_ballot": "зайвий бюлетень",
    "extra_data": "зайві дані в бюлетені",
    "duplicate_id": "однаковий ID у двох наборах",
    "hash_mismatch": "хеш не відповідає бюлетеню",
}


def show_sets(voter, pub):
    print("\nКроки 2–3. Виборець формує 10 наборів бюлетенів: у кожному наборі по одному")
    print("бюлетеню для кожного кандидата; усі бюлетені набору мають однаковий ID,")
    print("ID різних наборів різні (випадкові 19-значні числа). ID знає лише виборець:")
    for s in voter.sets:
        print(f"  Набір №{s.index + 1:<3} ID = {s.ballot_id}")
    first = voter.sets[0]
    print("\n  Склад набору №1:")
    for text in first.ballots:
        print(f"    «{text}»")

    print("\nКрок 4. Хеш кожного бюлетеня H (за модулем n ВК), випадковий множник r")
    print("(НСД(r, n) = 1) і замаскований хеш H' = H·r^e mod n. Числа скорочено:")
    print(f"  {'Набір':<8}{'Кандидат':<10}{'H':<26}{'r':<26}{'H' + chr(39)}")
    for s in voter.sets:
        for text, item in zip(s.ballots, s.masked):
            candidate = parse_ballot(text)[1]
            print(f"  №{s.index + 1:<7}№{candidate:<9}{short(item.h):<26}"
                  f"{short(item.r):<26}{short(item.h_masked)}")

    item = first.masked[0]
    print(f"\n  Повне обчислення для набору №1, бюлетеня «{first.ballots[0]}»:")
    print(f"    H  = {item.h}")
    print(f"    r  = {item.r}   (множник зберігає виборець)")
    print(f"    H' = H·r^e mod n = {item.h_masked}")


def show_set_check(commission, index, revealed_set, masked_row):
    pub = commission.public_key
    print(f"\n  Повна перевірка набору №{index + 1} (так само ВК перевіряє кожен із 9 наборів):")
    for k, text in enumerate(revealed_set.ballots):
        h = square_hash(text, pub[1])
        r = revealed_set.multipliers[k]
        recomputed = blind(h, r, pub)
        print(f"    бюлетень «{text}»")
        print(f"      H            (ВК обчислила сама)       = {h}")
        print(f"      r            (розкритий множник)       = {r}")
        print(f"      H·r^e mod n                            = {recomputed}")
        print(f"      H'           (отримано на кроці 5)     = {masked_row[k]}")
        print(f"      збігаються: {yes_no(recomputed == masked_row[k])}")


def issuance(commission, voter, rng, title, expect_signed, tamper=None,
             unopened=None, detail="compact", note=None):
    number = scenario(title, note)
    pub = commission.public_key
    name = voter.full_name
    expected = "підписано" if expect_signed else "відмова"
    per_set = len(voter.candidate_ids)
    per_set_word = plural(per_set, "бюлетеню", "бюлетені", "бюлетенів")

    masked = voter.prepare_sets(pub, tamper)
    if detail == "full":
        show_sets(voter, pub)
    else:
        print(f"Кроки 2–4: виборець сформував {NUM_SETS} наборів по {per_set} {per_set_word}, "
              "обчислив хеші та замаскував їх.")
        for k, kind in (tamper or {}).items():
            text = TAMPER_TEXT[kind].format(k=k + 1, kk=(k + 1) % NUM_SETS + 1)
            print(f"  [Порушення виборця] {text}.")

    request = commission.receive_masked_sets(name, masked)
    decision = (f"РІШЕННЯ: {request.reason}" if request.accepted
                else f"РІШЕННЯ: ВІДМОВА — {request.reason}")
    if detail == "full":
        print(f"\nКрок 5. Виборець надсилає ВК {NUM_SETS} наборів замаскованих хешів "
              f"({sum(len(s) for s in masked)} значень).")
        print(f"[ВК] перевірка 1: виборець є у списку виборців          : {yes_no(request.in_list)}")
        print(f"[ВК] перевірка 2: підписаний набір раніше не видавався  : {yes_no(request.not_received_before)}")
        print(f"[ВК] перевірка 3: 10 наборів коректних хешів            : {yes_no(request.sets_ok)}")
        print(f"[ВК] {decision}")
    else:
        print(f"Крок 5: ВК перевірила виборця. У списку виборців — {yes_no(request.in_list)}; "
              f"підписаний набір раніше не видавався — {yes_no(request.not_received_before)}.")
        print(f"        {decision}")
    if not request.accepted:
        record(number, title, expected, "відмова")
        return None

    indices = commission.choose_sets_to_reveal(name, rng, unopened)
    closed = [i for i in range(NUM_SETS) if i not in indices][0]
    prefix6 = "Крок 6. " if detail == "full" else "Крок 6: "
    print(f"{prefix6}ВК випадково обрала 9 наборів для розкриття: {numbers(i + 1 for i in indices)}.")
    print(f"        Набір №{closed + 1} залишається нерозкритим.")
    if unopened is not None:
        print("        (Для відтворюваності сценарію нерозкритий набір зафіксовано.)")

    revealed = voter.reveal(indices)
    n_revealed = sum(len(r.ballots) for r in revealed.values())
    prefix7 = "Крок 7. " if detail == "full" else "Крок 7: "
    print(f"{prefix7}виборець розкрив 9 наборів: передав {n_revealed} "
          f"{plural(n_revealed, 'початковий бюлетень', 'початкові бюлетені', 'початкових бюлетенів')} "
          "та стільки ж множників маскування;")
    print(f"        для набору №{closed + 1} нічого не передається.")

    report = commission.process_reveal(name, revealed)
    if detail == "full":
        print("\nКрок 8. ВК перевіряє розкриті набори: по одному бюлетеню для кожного кандидата, "
              "однаковий ID,")
        print("відсутність зайвих даних, ID наборів попарно різні, а також H·r^e mod n = H' "
              "для кожного бюлетеня.")
        first_checked = report.set_checks[0].index
        show_set_check(commission, first_checked, revealed[first_checked], masked[first_checked])
    elif detail == "table":
        print("Крок 8. ВК перевіряє 9 розкритих наборів (структура, ID, H·r^e mod n = H'):")
    if detail in ("full", "table"):
        print(f"\n  {'Набір':<8}{'ID набору':<22}{'бюлетенів':<11}{'структура':<11}"
              f"{'хеші збігаються':<17}{'результат'}")
        by_index = {c.index: c for c in report.set_checks}
        for i in range(NUM_SETS):
            if i == closed:
                print(f"  №{i + 1:<7}не розкривається (ID ВК невідомий)")
                continue
            c = by_index[i]
            structure_ok = not any("хеш" not in p for p in c.problems)
            hashes = f"{sum(c.hash_checks)} з {len(c.hash_checks)}"
            id_text = str(c.ballot_id) if c.ballot_id is not None else "немає єдиного ID"
            print(f"  №{i + 1:<7}{id_text:<22}{c.n_ballots:<11}{'ТАК' if structure_ok else 'НІ':<11}"
                  f"{hashes:<17}{'ОК' if c.ok else 'ПОМИЛКА'}")
    else:
        total = sum(len(c.hash_checks) for c in report.set_checks)
        good = sum(sum(c.hash_checks) for c in report.set_checks)
        print(f"Крок 8: ВК перевірила 9 розкритих наборів: хеші H·r^e mod n = H' збігаються "
              f"для {good} з {total} бюлетенів.")
    problems = [(c.number, p) for c in report.set_checks for p in c.problems]
    for set_number, problem in problems:
        print(f"  ✗ набір №{set_number}: {problem}")
    for problem in report.problems:
        print(f"  ✗ {problem}")
    if report.ok:
        print("  Усі 9 розкритих наборів сформовано правильно, ID наборів попарно різні.")

    if not report.ok:
        print("Крок 9: РІШЕННЯ ВК: у підписанні ВІДМОВЛЕНО — виявлено некоректний набір. "
              "Виборця у реєстрі НЕ позначено.")
        record(number, title, expected, "відмова")
        return None

    n_sig = len(report.signatures)
    if detail == "full":
        print(f"\nКрок 9. ВК вважає нерозкритий набір №{closed + 1} коректним і підписує своїм")
        print("закритим ключем кожен його замаскований хеш: S' = (H')^d mod n.")
        for k, s_masked in enumerate(report.signatures, 1):
            print(f"    S'_{k} = {s_masked}")
        print("  У реєстрі ВК позначено: виборець отримав підписаний набір. "
              "ID нерозкритого набору ВК не знає.")
    else:
        print(f"Крок 9: ВК підписала {n_sig} "
              f"{plural(n_sig, 'замаскований хеш', 'замасковані хеші', 'замаскованих хешів')} "
              f"нерозкритого набору №{closed + 1} і позначила виборця у реєстрі.")

    valid = voter.receive_signatures(report.signatures, pub)
    if detail == "full":
        print("\nКрок 10. Виборець знімає маскування: S = S'·r^(-1) mod n, і перевіряє підписи:")
        chosen = voter.sets[voter.unopened_index]
        for (text, signature), item, s_masked in zip(voter.signed, chosen.masked, report.signatures):
            hc = pow(signature, pub[0], pub[1])
            print(f"    бюлетень «{text}»")
            print(f"      r^(-1) mod n                   = {mod_inverse(item.r, pub[1])}")
            print(f"      S = S'·r^(-1) mod n            = {signature}")
            print(f"      Hc = S^e mod n                 = {hc}")
            print(f"      H = хеш бюлетеня               = {item.h}")
            print(f"      Hc = H (підпис ВК дійсний)     : {yes_no(hc == item.h)}")
    else:
        print(f"Крок 10: виборець зняв маскування й перевірив підписи ВК ({n_sig} "
              f"{plural(n_sig, 'підпис', 'підписи', 'підписів')}): усі дійсні — {yes_no(valid)}.")

    VIEW[name] = {
        "masked": [list(row_) for row_ in masked],
        "blind_signatures": list(report.signatures),
        "revealed_ids": [c.ballot_id for c in report.set_checks],
        "unopened": closed,
    }
    record(number, title, expected, "підписано" if valid else "відмова")
    return report



def row(label, name, value, width=46):
    return f"{'[' + label + ']':<11}{name:<{width}}: {value}"


def sender_lines(label, text, signature, message, signature_note=""):
    return [
        row(label, "бюлетень", f"«{text}»"),
        row(label, f"підпис S{signature_note}", short(signature, 40)),
        row(label, "текст для шифрування",
            f"«{text}{SIGNATURE_SEPARATOR}{short(signature, 20)}»"),
        row(label, "шифрування відкритим ключем ВК", blocks_short(message.blocks)),
        row(label, "ПІБ та інші персональні дані", "не передаються"),
    ]


def deliver(commission, title, message, expect_accept, lines=(), note=None, detail="full"):
    number = scenario(title, note)
    for line in lines:
        print(line)
    report = commission.receive_ballot(message)
    if detail == "full":
        if not report.decrypt_ok:
            print(row("ВК", "розшифрування закритим ключем ВК", "ПОМИЛКА"))
        elif not report.format_ok:
            shown = report.text if len(report.text) <= 70 else report.text[:69] + "…"
            print(row("ВК", "розшифроване повідомлення", f"«{shown}»"))
            print(row("ВК", "формат «бюлетень + ЕЦП ВК» коректний", yes_no(False)))
        else:
            print(row("ВК", "розшифрований бюлетень", f"«{report.text}»"))
            print(row("ВК", "ЕЦП ВК з розшифрованого тексту", short(report.signature, 40)))
            print(row("ВК", "ID бюлетеня / кандидат", f"{report.ballot_id} / №{report.candidate_id}"))
            print(row("ВК", "перевірка 1: ЕЦП ВК дійсний (H == Hc)", yes_no(report.signature_ok)))
            print(f"{'':11}{'H  — хеш отриманого бюлетеня':<46}= {report.hash_from_text}")
            print(f"{'':11}{'Hc — хеш з ЕЦП (S^e mod n)':<46}= {report.hash_from_signature}")
            print(row("ВК", "перевірка 2: ID раніше не використовувався", yes_no(report.id_unique)))
    else:
        if report.format_ok:
            print(f"[ВК] розшифровано «{report.text}»; ЕЦП ВК дійсний — {yes_no(report.signature_ok)}; "
                  f"ID унікальний — {yes_no(report.id_unique)}")
        else:
            print(f"[ВК] розшифровано, формат коректний — {yes_no(report.format_ok)}")
    verdict = "ПРИЙНЯТО до підрахунку" if report.accepted else "ВІДХИЛЕНО"
    print(f"[ВК] РІШЕННЯ: бюлетень {verdict} — {report.reason}")
    record(number, title, "прийнято" if expect_accept else "відхилено",
           "прийнято" if report.accepted else "відхилено")
    return report


def election_1(rng):
    header("ВИБОРИ №1. 5 виборців, 2 кандидати: усі кроки протоколу та перевірки")

    commission = ElectionCommission(CANDIDATES, rng)
    for name in VOTER_NAMES:
        commission.register_voter(name)
    voters = [Voter(name, list(CANDIDATES), rng) for name in VOTER_NAMES]
    outsider = Voter(OUTSIDER_NAME, list(CANDIDATES), rng)
    koval, shev, bond, tkach, melnyk = voters
    pub = commission.public_key

    print("\nКрок 1. ВК формує список виборців (власні ключі виборцям не потрібні):")
    for index, name in enumerate(commission.voter_list, 1):
        print(f"  {index}. {name}")
    print("\nКрок 1. ВК формує список кандидатів:")
    for candidate_id, name in commission.candidates.items():
        print(f"  №{candidate_id}: {name}")
    print("\nКрок 1. ВК генерує власну пару ключів RSA (для сліпого підпису та розшифрування бюлетенів):")
    show_keypair("Виборча комісія", commission.keys)
    print("\n  ОПУБЛІКОВАНО відкритий ключ ВК (закритий ключ (d, n) не публікується):")
    print(f"    e = {pub[0]}")
    print(f"    n = {pub[1]}")

    header("ОТРИМАННЯ ПІДПИСАНИХ НАБОРІВ БЮЛЕТЕНІВ (кроки 2–10)")
    issuance(commission, koval, rng,
             "Коваленко отримує підписаний набір бюлетенів [позитивний]", True, detail="full")
    issuance(commission, outsider, rng,
             "Савчук просить підписаний набір, але його немає у списку виборців "
             "[негативний: перевірка на кроці 5]", False)
    issuance(commission, koval, rng,
             "Коваленко просить підписаний набір вдруге [негативний: повторне отримання]", False)
    issuance(commission, shev, rng,
             "Шевченко формує некоректний набір №4, а ВК випадково обирає його для розкриття "
             "[негативний: некоректний набір серед 9]", False,
             tamper={3: "different_id"}, unopened=6, detail="table",
             note="виборець міг би виграти від такого набору: маючи бюлетені з різними ID, він "
                  "проголосував би двічі. Серед 9 розкритих наборів ВК цю помилку виявляє.")
    for kind, bad in [("missing_ballot", 1), ("extra_ballot", 8), ("extra_data", 2),
                      ("hash_mismatch", 5), ("duplicate_id", 3)]:
        issuance(commission, shev, rng,
                 f"Шевченко формує некоректний набір №{bad + 1} ({TAMPER_NAME[kind]}) "
                 "[негативний: некоректний набір серед 9]", False,
                 tamper={bad: kind}, unopened=0)
    issuance(commission, shev, rng,
             "Шевченко формує правильні набори [позитивний]", True,
             note="за буквою протоколу виборця, у якого не вийшло обманути ВК, не заблоковано: "
                  "позначка про видачу підписаного набору ставиться лише на кроці 9.")
    issuance(commission, bond, rng, "Бондаренко отримує підписаний набір [позитивний]", True)
    issuance(commission, tkach, rng, "Ткаченко отримує підписаний набір [позитивний]", True)
    issuance(commission, melnyk, rng, "Мельник отримує підписаний набір [позитивний]", True)

    header("ПОДАННЯ ГОЛОСІВ (кроки 11–13). Голоси надсилаються анонімно, у довільному порядку")
    text, signature = koval.signed[0]
    message = koval.cast(1, pub)
    deliver(commission, "Коваленко голосує за кандидата №1 [позитивний]", message, True,
            note="підпис ВК передається цифрами всередині зашифрованого тексту разом із бюлетенем. "
                 "RSA шифрує символи окремо й детерміновано, тому однакові початки різних "
                 "повідомлень («ID=…») дають однакові початкові блоки шифротексту — це властивість "
                 "підручникового RSA без випадкового доповнення.",
            lines=["Крок 11. Виборець обирає з підписаного набору бюлетень за свого кандидата",
                   "(інші бюлетені набору не використовує), додає до нього підпис ВК",
                   "та шифрує повідомлення відкритим ключем ВК.",
                   "Крок 12. Повідомлення надсилається до ВК без ПІБ:"]
            + sender_lines("Виборець", text, signature, message))
    assert commission.tally().accepted_total == 1

    text2, signature2 = koval.signed[1]
    message = koval.cast(2, pub)
    deliver(commission,
            "Коваленко надсилає ще один бюлетень з того самого підписаного набору (за кандидата №2) "
            "[негативний: повторне використання ID]", message, False,
            note="обидва бюлетені набору мають дійсний підпис ВК і однаковий ID, тому перевірка "
                 "ЕЦП проходить, але ID уже використано: до підрахунку береться лише перший.",
            lines=sender_lines("Виборець", text2, signature2, message))

    fake_text = ballot_text(rng.randrange(10**18, 10**19), 1)
    fake_signature = rng.randrange(2, pub[1])
    message = build_ballot_message(fake_text, fake_signature, pub)
    deliver(commission,
            "Бюлетень, сформований самостійно, з довільним підписом [негативний: ЕЦП недійсний]",
            message, False,
            note="без закритого ключа ВК сформувати дійсний підпис неможливо.",
            lines=sender_lines("Порушник", fake_text, fake_signature, message,
                               signature_note=" (довільне число)"))

    forged_text = ballot_text(rng.randrange(10**18, 10**19), 2)
    hash_as_signature = square_hash(forged_text, pub[1])
    message = build_ballot_message(forged_text, hash_as_signature, pub)
    deliver(commission,
            "Порушник підставляє замість підпису хеш бюлетеня H [негативний: ЕЦП недійсний]",
            message, False,
            note="підпис передається не окремим числом, а цифрами всередині зашифрованого тексту. "
                 "Якби він ішов окремим блоком, який ВК розшифровує своїм закритим ключем, число H "
                 "після розшифрування давало б H^d — дійсний підпис, і голос можна було б "
                 "підробити без участі ВК. Тут для S = H перевірка S^e = H не виконується.",
            lines=sender_lines("Порушник", forged_text, hash_as_signature, message,
                               signature_note=" (= хеш H)"))

    old_id = parse_ballot(text)[0]
    changed_text = ballot_text(old_id + 1, 1)
    message = build_ballot_message(changed_text, signature, pub)
    deliver(commission,
            "Коваленко змінює ID у підписаному бюлетені, щоб обійти перевірку ID "
            "[негативний: ЕЦП недійсний]", message, False,
            note="ID входить до підписаних даних, тому його зміна робить підпис ВК недійсним.",
            lines=sender_lines("Виборець", changed_text, signature, message,
                               signature_note=" (від початкового бюлетеня)"))

    for voter, choice, label in [(melnyk, 2, "Мельник"), (tkach, 1, "Ткаченко"),
                                 (shev, 2, "Шевченко"), (bond, 1, "Бондаренко")]:
        deliver(commission, f"{label} голосує за кандидата №{choice} [позитивний]",
                voter.cast(choice, pub), True, detail="compact")

    header("ПІДРАХУНОК І ПУБЛІКАЦІЯ РЕЗУЛЬТАТІВ (крок 14)")
    number = scenario("ВК підраховує прийняті голоси та публікує результати [позитивний]")
    result = commission.tally()
    print(f"Прийнято бюлетенів: {result.accepted_total};  відхилено повідомлень: {result.rejected_total}")
    print(f"З прийнятих: зараховано кандидатам {result.valid_total}, зіпсованих {result.spoiled}\n")
    for candidate_id, name in commission.candidates.items():
        count = result.counts[candidate_id]
        share = count / result.valid_total if result.valid_total else 0
        print(f"  Кандидат №{candidate_id} ({name}): {count} ({percent(share)}) {'█' * count}")
    if result.status == "winner":
        leader = result.leaders[0]
        print(f"\nРЕЗУЛЬТАТ: перемагає кандидат №{leader} ({commission.candidates[leader]}).")
    elif result.status == "tie":
        print(f"\nРЕЗУЛЬТАТ: голоси розподілилися порівну між кандидатами {numbers(result.leaders)}.")
    else:
        print("\nРЕЗУЛЬТАТ: жодного дійсного голосу не подано.")
    published = commission.publish()
    print("\nОпублікований список: ID, підписаний бюлетень, підпис ВК (ПІБ у списку немає):")
    for entry in published:
        print(f"  {entry.ballot_id}  «{entry.text}»  S = {short(entry.signature, 30)}")
    print(f"Усі підписи ВК у списку дійсні (перевірка доступна кожному): "
          f"{yes_no(verify_published(published, pub))}")
    record(number, "Підрахунок голосів (вибори №1)",
           "№1: 3, №2: 2; переможець №1; прийнято 5, відхилено 4",
           f"{', '.join(f'№{c}: {n}' for c, n in result.counts.items())}; "
           f"{'переможець №' + str(result.leaders[0]) if result.status == 'winner' else result.status}; "
           f"прийнято {result.accepted_total}, відхилено {result.rejected_total}")

    number = scenario("Кожен виборець знаходить свій ID у списку та перевіряє свій голос [позитивний]")
    all_found = True
    for voter in voters:
        ballot_id, found, same = voter.verify_in_published(published)[0]
        all_found = all_found and found and same
        print(f"  {voter.full_name}: ID {ballot_id} — знайдено у списку: {yes_no(found)}; "
              f"бюлетень і підпис збігаються: {yes_no(same)}")
    record(number, "Виборці перевіряють свої голоси у списку", "усі 5 голосів знайдено",
           "усі 5 голосів знайдено" if all_found else "є розбіжності")

    number = scenario("ВК підміняє чийсь голос в опублікованому списку [негативний: підміну виявлено]",
                      note="ВК не може виготовити підпис для змінених даних, тому підміна не проходить перевірку.")
    victim_id = tkach.verify_in_published(published)[0][0]
    position = [e.ballot_id for e in published].index(victim_id)
    victim_choice = parse_ballot(published[position].text)[1]
    forged_text = ballot_text(victim_id, 2 if victim_choice == 1 else 1)
    forged = list(published)
    forged[position] = replace(forged[position], text=forged_text)
    list_ok = verify_published(forged, pub)
    _, found, same = tkach.verify_in_published(forged)[0]
    print(f"У списку голос із ID {victim_id} змінено: «{published[position].text}» → «{forged_text}»")
    print(f"Підписи ВК у списку дійсні (перевірка будь-ким)            : {yes_no(list_ok)}")
    print(f"Ткаченко знаходить свій ID: {yes_no(found)}; бюлетень збігається з надісланим: {yes_no(same)}")
    record(number, "Підміна голосу у списку", "підміну виявлено",
           "підміну виявлено" if (not list_ok and found and not same) else "НЕ виявлено")

    number = scenario("ВК вилучає чийсь голос з опублікованого списку [негативний: вилучення виявлено]")
    victim_id = bond.verify_in_published(published)[0][0]
    trimmed = [e for e in published if e.ballot_id != victim_id]
    _, found, same = bond.verify_in_published(trimmed)[0]
    print(f"У списку лишилось {len(trimmed)} {plural(len(trimmed), 'запис', 'записи', 'записів')} "
          f"із {len(published)}.")
    print(f"Бондаренко шукає свій ID {victim_id}: знайдено — {yes_no(found)}")
    record(number, "Вилучення голосу зі списку", "вилучення виявлено",
           "вилучення виявлено" if not found else "НЕ виявлено")

    anonymity(commission, voters, published)
    return commission


def anonymity(commission, voters, published):
    pub = commission.public_key
    n = pub[1]
    number = scenario("Аналіз анонімності: чи може ВК пов'язати голос з виборцем")
    seen_values, seen_ids = set(), set()
    for view in VIEW.values():
        for row in view["masked"]:
            seen_values.update(row)
        seen_values.update(view["blind_signatures"])
        seen_ids.update(view["revealed_ids"])
    votes = [(e.ballot_id, square_hash(e.text, n), e.signature) for e in published]

    koval = voters[0]
    view = VIEW[koval.full_name]
    print("Що ВК бачила, підписуючи набір Коваленка (кроки 5–9):")
    for k, value in enumerate(view["masked"][view["unopened"]], 1):
        print(f"  замаскований хеш H'_{k} нерозкритого набору = {short(value, 40)}")
    for k, value in enumerate(view["blind_signatures"], 1):
        print(f"  сліпий підпис       S'_{k}                  = {short(value, 40)}")
    print("  ID розкритих наборів (за ними голоси не впізнати: ID нерозкритого набору ВК не знає):")
    ids = [str(i) for i in view["revealed_ids"]]
    for start in range(0, len(ids), 3):
        print("    " + "   ".join(ids[start:start + 3]))
    print("Що ВК бачить у поданих голосах (крок 13): ID, бюлетень, його хеш H та підпис S:")
    for ballot_id, h, s in votes:
        print(f"  ID {ballot_id}   H = {short(h, 20)}   S = {short(s, 20)}")

    no_value_link = not any(h in seen_values or s in seen_values for _, h, s in votes)
    no_id_link = not any(ballot_id in seen_ids for ballot_id, _, _ in votes)
    print(f"\nВсього ВК знає {len(seen_ids)} ID розкритих наборів ({len(VIEW)} виборців по 9).")
    print(f"Чи збігається H або S якогось голосу зі значеннями H', S' з видачі підписів: "
          f"{yes_no(not no_value_link)}")
    print(f"Чи збігається ID якогось голосу з ID розкритих наборів                    : "
          f"{yes_no(not no_id_link)}")

    h_masked = view["masked"][view["unopened"]][0]
    print("\nСліпота підпису: для замаскованого хешу H'_1 Коваленка ВК (знаючи d) може підібрати "
          "множник r,")
    print("який «пояснює» H' будь-яким із 5 поданих бюлетенів, тому за H' бюлетень не визначити:")
    explainable = True
    d = commission.keys.d
    for entry in published:
        h_j = square_hash(entry.text, n)
        r_j = pow((h_masked * mod_inverse(h_j, n)) % n, d, n)
        fits = blind(h_j, r_j, pub) == h_masked
        explainable = explainable and fits
        print(f"  бюлетень з ID {entry.ballot_id}: існує r = {short(r_j, 20)}, H' = H·r^e mod n — "
              f"{yes_no(fits)}")
    linked = not (no_value_link and no_id_link and explainable)
    record(number, "Аналіз анонімності (зв'язок голосу з виборцем)", "зв'язати неможливо",
           "ЗНАЙДЕНО ЗВ'ЯЗОК" if linked else "зв'язати неможливо")


def election_2(rng, trials):
    header("ВИБОРИ №2. Ймовірнісний характер перевірки 9 із 10 наборів")
    commission = ElectionCommission(CANDIDATES, rng)
    print("ВК згенерувала нову пару ключів RSA для виборів №2.")

    number = scenario(f"Симуляція: {trials} спроб шахрайства з одним некоректним набором із 10 "
                      "[ймовірнісна перевірка]",
                      note="кожен шахрай ховає некоректний набір (різні ID у наборі) на випадковому "
                           "місці; ВК випадково обирає нерозкритий набір. Якщо некоректний набір "
                           "опинився серед розкритих, його виявлено.")
    caught = 0
    for k in range(trials):
        name = f"Шахрай {k + 1}"
        commission.register_voter(name)
        cheater = Voter(name, list(CANDIDATES), rng)
        bad = rng.randrange(NUM_SETS)
        outcome = issue_signed_set(commission, cheater, rng, tamper={bad: "different_id"})
        caught += 0 if outcome.signed else 1
    rate = caught / trials
    print(f"Виявлено {caught} із {trials} спроб ({percent(rate)}); теоретична ймовірність: "
          f"9 із 10 = 90,0 %.")
    within = abs(rate - 0.9) <= 0.04 if trials >= 500 else abs(rate - 0.9) <= 0.12
    record(number, "Імовірність виявлення некоректного набору", "близько 90 %",
           percent(rate), ok=within)

    commission2 = ElectionCommission(CANDIDATES, rng)
    commission2.register_voter(SNEAKY_NAME)
    sneaky = Voter(SNEAKY_NAME, list(CANDIDATES), rng)
    pub = commission2.public_key
    issuance(commission2, sneaky, rng,
             "Виборець формує некоректний набір №5, і ВК випадково залишає саме його нерозкритим "
             "[ймовірність 10 %: порушення не виявлено]", True,
             tamper={4: "different_id"}, unopened=4, detail="compact",
             note="некоректний набір опинився єдиним нерозкритим, тому ВК не може його перевірити "
                  "і підписує.")
    print("У виборця тепер є два підписані бюлетені з різними ID:")
    for text, _ in sneaky.signed:
        print(f"  «{text}»")
    reports = []
    for position, label in enumerate(("перший", "другий")):
        message = sneaky.cast_signed(position, pub)
        reports.append(deliver(
            commission2, f"Виборець надсилає {label} бюлетень зі свого підписаного набору "
                         "[обмеження протоколу: приймається]", message, True, detail="compact"))
    accepted = commission2.tally().accepted_total
    print(f"\nПрийнято бюлетенів від одного виборця: {accepted}. Повторне голосування не виявлено: "
          "розкриття 9 із 10 наборів дає лише ймовірнісну гарантію.")
    number = len(SUMMARY) + 1
    record(number, "Наслідок: виборець голосує двічі (невиявлений некоректний набір)",
           "прийнято 2 бюлетені одного виборця",
           f"прийнято {accepted} {plural(accepted, 'бюлетень', 'бюлетені', 'бюлетенів')} одного виборця")


def show_summary():
    header("ПІДСУМОК ПЕРЕВІРОК")
    all_match = True
    for number, title, expected, got, ok in SUMMARY:
        all_match = all_match and ok
        mark = "збіг" if ok else "РОЗБІЖНІСТЬ"
        print(f"{number:>2}. {title}")
        print(f"      очікувано: {expected}")
        print(f"      отримано : {got}   [{mark}]")
    print()
    print("Усі сценарії відпрацювали як очікувалось." if all_match
          else "УВАГА: є розбіжності між очікуваним і отриманим результатом!")
    return all_match


def main():
    parser = argparse.ArgumentParser(description="Демонстрація протоколу Е-голосування зі сліпими підписами")
    parser.add_argument("--seed", type=int, default=2026,
                        help="seed для відтворюваної генерації (за замовчуванням 2026)")
    parser.add_argument("--random-keys", action="store_true",
                        help="щоразу генерувати нові випадкові значення")
    parser.add_argument("--trials", type=int, default=1000,
                        help="кількість спроб у симуляції вибору 9 із 10 наборів (за замовчуванням 1000)")
    args = parser.parse_args()

    rng = random.SystemRandom() if args.random_keys else random.Random(args.seed)

    election_1(rng)
    election_2(rng, args.trials)
    ok = show_summary()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
