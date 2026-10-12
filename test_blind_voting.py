import random
import sys
from dataclasses import replace

from rsa_core import generate_keypair, square_hash, encrypt_text, encrypt_int
from blind_core import gcd
from blind_voting import (
    SIGNATURE_SEPARATOR,
    NUM_SETS, ID_LOW, TAMPER_KINDS,
    ElectionCommission, Voter, BallotMessage,
    ballot_text, parse_ballot, build_ballot_message,
    issue_signed_set, verify_published,
)

try:
    sys.stdout.reconfigure(encoding="utf-8")
except AttributeError:
    pass

NAMES = [
    "Коваленко Олександр Іванович",
    "Шевченко Марія Петрівна",
    "Бондаренко Андрій Сергійович",
    "Ткаченко Оксана Миколаївна",
    "Мельник Дмитро Васильович",
]
OUTSIDER = "Савчук Ігор Олегович"
CANDIDATES = {1: "Іваненко Тарас Олексійович", 2: "Мороз Ірина Степанівна"}

passed = 0
failed = 0


def check(name, condition):
    global passed, failed
    if condition:
        passed += 1
        print(f"[PASS] {name}")
    else:
        failed += 1
        print(f"[FAIL] {name}")


def make_world(seed=2026, voters_count=5):
    rng = random.Random(seed)
    commission = ElectionCommission(CANDIDATES, rng)
    names = NAMES[:voters_count]
    for name in names:
        commission.register_voter(name)
    voters = [Voter(name, list(CANDIDATES), rng) for name in names]
    outsider = Voter(OUTSIDER, list(CANDIDATES), rng)
    return commission, voters, outsider, rng


def has(problems, keyword):
    return any(keyword in p for p in problems)


print("=== 1. Підготовка виборів (крок 1) ===")
commission, voters, outsider, rng = make_world()
pub = commission.public_key
check("у списку ВК 5 виборців, жоден ще не отримував підписаний набір",
      len(commission.voter_list) == 5 and not any(commission.signed_registry.values()))
check("у списку 2 кандидати", len(commission.candidates) == 2)
check("ВК має власну пару ключів RSA (модуль ~256 біт), відкритий ключ (e, n) публічний",
      250 <= pub[1].bit_length() <= 256 and (commission.keys.e * commission.keys.d)
      % commission.keys.phi == 1)
check("виборці не мають власних ключів RSA",
      not any(hasattr(v, "keys") for v in voters))

print("\n=== 2. Формат бюлетеня ===")
sample = ballot_text(7283610958472016351, 2)
check("формат бюлетеня: ID=<19 цифр>; Кандидат №N",
      sample == "ID=7283610958472016351; Кандидат №2")
check("розбір: (ID, кандидат)", parse_ballot(sample) == (7283610958472016351, 2))
check("зайві дані в тексті відхиляються", parse_ballot(sample + "; бонус") is None)
check("ID не з 19 цифр відхиляється",
      parse_ballot("ID=12345; Кандидат №1") is None
      and parse_ballot("ID=72836109584720163510; Кандидат №1") is None)
check("ID з нулем попереду відхиляється",
      parse_ballot("ID=0283610958472016351; Кандидат №1") is None)
check("кандидат №0 та порожній номер відхиляються",
      parse_ballot("ID=7283610958472016351; Кандидат №0") is None
      and parse_ballot("ID=7283610958472016351; Кандидат №") is None)
check("бюлетень без ID відхиляється", parse_ballot("Кандидат №1") is None)

print("\n=== 3. Виборець формує 10 наборів (кроки 2-4) ===")
v0 = voters[0]
masked = v0.prepare_sets(pub)
check("сформовано 10 наборів", len(v0.sets) == NUM_SETS)
check("кожен набір містить по одному бюлетеню для кожного кандидата",
      all([parse_ballot(t)[1] for t in s.ballots] == [1, 2] for s in v0.sets))
check("усі бюлетені одного набору мають однаковий ID",
      all(len({parse_ballot(t)[0] for t in s.ballots}) == 1 for s in v0.sets))
check("ID різних наборів відрізняються", len({s.ballot_id for s in v0.sets}) == NUM_SETS)
check("ID - 19-значні числа", all(ID_LOW <= s.ballot_id < 10 * ID_LOW for s in v0.sets))
check("до ВК передається 10 наборів по 2 замасковані хеші",
      len(masked) == 10 and all(len(s) == 2 for s in masked))
check("хеші бюлетенів обчислено за модулем ВК (H = square_hash(текст, n))",
      all(m.h == square_hash(t, pub[1]) for s in v0.sets for t, m in zip(s.ballots, s.masked)))
check("замасковані хеші відрізняються від початкових",
      all(m.h_masked != m.h for s in v0.sets for m in s.masked))
check("кожен бюлетень має власний множник маскування, взаємно простий з n",
      len({m.r for s in v0.sets for m in s.masked}) == 20
      and all(gcd(m.r, pub[1]) == 1 for s in v0.sets for m in s.masked))
check("у даних для ВК немає ні бюлетенів, ні множників",
      all(isinstance(x, int) for s in masked for x in s)
      and not any(str(s.ballot_id) in repr(masked) for s in v0.sets))

print("\n=== 4. Крок 5: перевірки ВК - позитивний і негативні сценарії ===")
req = commission.receive_masked_sets(v0.full_name, masked)
check("POSITIVE: виборець зі списку, що не отримував підписаний набір, - запит прийнято",
      req.accepted and req.in_list and req.not_received_before and req.sets_ok)

outsider.prepare_sets(pub)
req = commission.receive_masked_sets(outsider.full_name, outsider.masked_sets())
check("NEGATIVE: виборця немає у списку - відмова",
      not req.accepted and req.in_list is False)
check("NEGATIVE: наступні перевірки для стороннього не виконувались",
      req.not_received_before is None and req.sets_ok is None)

bad = [list(s) for s in masked]
req = commission.receive_masked_sets(v0.full_name, bad[:9])
check("NEGATIVE: надіслано 9 наборів замість 10 - відмова",
      not req.accepted and req.sets_ok is False)
bad[3][0] = pub[1] + 5
req = commission.receive_masked_sets(v0.full_name, bad)
check("NEGATIVE: замаскований хеш поза діапазоном - відмова",
      not req.accepted and req.sets_ok is False)
check("відмови на кроці 5 не позначають виборця у реєстрі",
      commission.signed_registry[v0.full_name] is False)

print("\n=== 5. Крок 6: ВК випадково обирає 9 із 10 наборів ===")
req = commission.receive_masked_sets(v0.full_name, masked)
idx = commission.choose_sets_to_reveal(v0.full_name, rng)
check("обрано 9 різних наборів з номерами 0..9",
      len(idx) == 9 and len(set(idx)) == 9 and all(0 <= i < NUM_SETS for i in idx))
check("рівно один набір залишається нерозкритим",
      len([i for i in range(NUM_SETS) if i not in idx]) == 1)
tmp_rng = random.Random(8)
dropped = []
for _ in range(300):
    commission2, (probe,), _, _ = make_world(seed=tmp_rng.randrange(10**6), voters_count=1)
    probe.prepare_sets(commission2.public_key)
    commission2.receive_masked_sets(probe.full_name, probe.masked_sets())
    chosen = commission2.choose_sets_to_reveal(probe.full_name, tmp_rng)
    dropped.append([i for i in range(NUM_SETS) if i not in chosen][0])
check("вибір випадковий: за 300 спроб нерозкритим буває кожен із 10 наборів",
      set(dropped) == set(range(NUM_SETS)))

print("\n=== 6. Кроки 7-10: коректний виборець отримує підписаний набір ===")
revealed = v0.reveal(idx)
check("виборець розкриває рівно 9 запитаних наборів",
      sorted(revealed) == sorted(idx) and len(revealed) == 9)
unopened_id = v0.sets[v0.unopened_index].ballot_id
check("початкові бюлетені та множники нерозкритого набору не передаються",
      v0.unopened_index not in revealed)
report = commission.process_reveal(v0.full_name, revealed)
check("POSITIVE: усі 9 наборів сформовано правильно - ВК підписує нерозкритий набір",
      report.ok and len(report.set_checks) == 9 and all(c.ok for c in report.set_checks)
      and not report.problems)
check("для кожного бюлетеня розкритих наборів хеш відповідає замаскованому",
      all(all(c.hash_checks) and len(c.hash_checks) == 2 for c in report.set_checks))
check("ВК підписала кожен замаскований хеш нерозкритого набору (2 сліпі підписи)",
      report.signatures is not None and len(report.signatures) == 2)
check("ВК позначила виборця у реєстрі: підписаний набір видано",
      commission.signed_registry[v0.full_name] is True)
check("виборець зняв маскування: обидва підписи ВК дійсні",
      v0.receive_signatures(report.signatures, pub))
check("ВК не знає ID нерозкритого набору",
      str(unopened_id) not in repr(vars(commission))
      and unopened_id not in {c.ballot_id for c in report.set_checks})
check("ID розкритих наборів ВК знає (9 різних значень)",
      len({c.ballot_id for c in report.set_checks}) == 9)

print("\n=== 7. Негативний: повторне отримання підписаного набору ===")
again = v0.prepare_sets(pub)
req = commission.receive_masked_sets(v0.full_name, again)
check("NEGATIVE: виборець, який уже отримав підписаний набір, отримує відмову",
      not req.accepted and req.not_received_before is False and req.in_list is True)
check("повторний запит не створює активного сеансу",
      v0.full_name not in commission._sessions)

print("\n=== 8. Негативний: некоректно сформований набір серед 9 розкритих ===")
for kind, keyword in [
    ("missing_ballot", "відсутні бюлетені"),
    ("different_id", "різні ID"),
    ("extra_ballot", "зайві бюлетені"),
    ("extra_data", "некоректний формат"),
    ("hash_mismatch", "не відповідає замаскованому"),
    ("duplicate_id", "однаковий ID"),
]:
    world, (cheater, *_), _, wrng = make_world(seed=100 + TAMPER_KINDS.index(kind))
    res = issue_signed_set(world, cheater, wrng, tamper={4: kind}, unopened=7)
    rep = res.reveal
    flagged = [c.number for c in rep.set_checks if not c.ok]
    where = rep.problems if kind == "duplicate_id" else [
        p for c in rep.set_checks for p in c.problems]
    check(f"NEGATIVE [{kind}]: ВК виявляє некоректний набір - підписання відмовлено",
          not rep.ok and rep.signatures is None and not res.signed)
    check(f"NEGATIVE [{kind}]: проблема описана («{keyword}»)", has(where, keyword))
    if kind != "duplicate_id":
        check(f"NEGATIVE [{kind}]: позначено саме набір №5, решта розкритих наборів коректні",
              flagged == [5])
    check(f"NEGATIVE [{kind}]: виборця не позначено як такого, що отримав підписаний набір",
          world.signed_registry[cheater.full_name] is False)

print("\n=== 9. Негативний: порушення порядку розкриття ===")
world, (cheat, *_), _, wrng = make_world(seed=31)
cheat.prepare_sets(world.public_key)
world.receive_masked_sets(cheat.full_name, cheat.masked_sets())
asked = world.choose_sets_to_reveal(cheat.full_name, wrng, unopened=2)
rep = world.process_reveal(cheat.full_name, cheat.reveal(range(NUM_SETS)))
check("NEGATIVE: виборець розкриває всі 10 наборів - відмова, ID десятого не стає відомим",
      not rep.ok and has(rep.problems, "не запитувались") and rep.signatures is None)
cheat.prepare_sets(world.public_key)
world.receive_masked_sets(cheat.full_name, cheat.masked_sets())
asked = world.choose_sets_to_reveal(cheat.full_name, wrng, unopened=2)
rep = world.process_reveal(cheat.full_name, cheat.reveal(asked[:-1]))
check("NEGATIVE: виборець розкриває лише 8 наборів - відмова",
      not rep.ok and has(rep.problems, "не розкрито"))
cheat.prepare_sets(world.public_key)
world.receive_masked_sets(cheat.full_name, cheat.masked_sets())
asked = world.choose_sets_to_reveal(cheat.full_name, wrng, unopened=2)
rep = world.process_reveal(cheat.full_name, cheat.reveal([i for i in range(NUM_SETS) if i != 5]))
check("NEGATIVE: виборець розкриває інші набори, ніж запитала ВК - відмова",
      not rep.ok and has(rep.problems, "не запитувались") and has(rep.problems, "не розкрито"))
rep = world.process_reveal(cheat.full_name, cheat.reveal(asked))
check("NEGATIVE: розкриття без активного запиту - відмова",
      not rep.ok and has(rep.problems, "немає активного запиту"))
check("жодна з відмов не позначила виборця у реєстрі",
      world.signed_registry[cheat.full_name] is False)
res = issue_signed_set(world, cheat, wrng)
check("за буквою протоколу невиявлений порушник не заблокований і може подати новий запит",
      res.signed and world.signed_registry[cheat.full_name] is True)

print("\n=== 10. Ймовірнісний характер перевірки (90 %) ===")
world, _, _, srng = make_world(seed=55, voters_count=1)
detected = 0
trials = 1000
for k in range(trials):
    name = f"Порушник {k}"
    world.register_voter(name)
    sneaky = Voter(name, list(CANDIDATES), srng)
    bad_index = srng.randrange(NUM_SETS)
    res = issue_signed_set(world, sneaky, srng, tamper={bad_index: "different_id"})
    detected += 0 if res.signed else 1
rate = detected / trials
check(f"один некоректний набір із 10 виявляється у ~90 % випадків (отримано {rate:.1%})",
      0.86 <= rate <= 0.94)
honest_ok = 0
for k in range(300):
    name = f"Чесний {k}"
    world.register_voter(name)
    honest = Voter(name, list(CANDIDATES), srng)
    honest_ok += issue_signed_set(world, honest, srng).signed
check("чесні виборці ніколи не отримують хибної відмови (300 з 300)", honest_ok == 300)

world, (sneak, *_), _, wrng = make_world(seed=77)
res = issue_signed_set(world, sneak, wrng, tamper={4: "different_id"}, unopened=4)
check("10 %: некоректний набір опинився нерозкритим - ВК його не виявляє й підписує",
      res.signed and res.signatures_ok)
ids_in_signed = {parse_ballot(t)[0] for t, _ in sneak.signed}
check("наслідок: у підписаному наборі бюлетені мають різні ID", len(ids_in_signed) == 2)
r1 = world.receive_ballot(sneak.cast_signed(0, world.public_key))
r2 = world.receive_ballot(sneak.cast_signed(1, world.public_key))
check("наслідок: такий виборець голосує двічі - обидва бюлетені приймаються",
      r1.accepted and r2.accepted and world.tally().accepted_total == 2)

world, (sneak, *_), _, wrng = make_world(seed=78)
res = issue_signed_set(world, sneak, wrng, tamper={4: "extra_ballot"}, unopened=4)
check("10 %: набір із зайвим бюлетенем у нерозкритому наборі також підписано", res.signed)
rep = world.receive_ballot(sneak.cast(3, world.public_key))
result = world.tally()
check("зайвий бюлетень (кандидат №3) приймається, але жодному кандидату не зараховується",
      rep.accepted and result.spoiled == 1 and result.valid_total == 0)

print("\n=== 11. Повний цикл: усі 5 виборців отримують підписані набори ===")
commission, voters, outsider, rng = make_world(seed=2026)
pub = commission.public_key
results = [issue_signed_set(commission, v, rng) for v in voters]
check("усі 5 виборців отримали підписаний набір, усі підписи дійсні",
      all(r.signed and r.signatures_ok for r in results)
      and all(commission.signed_registry.values()))
check("у кожного виборця унікальний ID нерозкритого набору (5 різних)",
      len({parse_ballot(v.signed[0][0])[0] for v in voters}) == 5)
check("жоден з ID нерозкритих наборів не відомий ВК",
      not any(str(parse_ballot(v.signed[0][0])[0]) in repr(vars(commission)) for v in voters))
check("кожен виборець має 2 підписані бюлетені з однаковим ID (по одному на кандидата)",
      all(len(v.signed) == 2 and parse_ballot(v.signed[0][0])[0] == parse_ballot(v.signed[1][0])[0]
          and [parse_ballot(t)[1] for t, _ in v.signed] == [1, 2] for v in voters))

print("\n=== 12. Подання голосів (кроки 11-13): позитивний сценарій ===")
msg = voters[0].cast(1, pub)
check("повідомлення не містить ПІБ чи інших персональних даних",
      set(vars(msg)) == {"blocks"})
check("бюлетень не передається у відкритому вигляді",
      all(b != ord(c) for b, c in zip(msg.blocks, voters[0].signed[0][0])))
check("підпис ВК передається у складі зашифрованого тексту разом із бюлетенем (не окремим блоком)",
      len(msg.blocks) > len(voters[0].signed[0][0]) + 70)
rep = commission.receive_ballot(msg)
check("POSITIVE: бюлетень з дійсним підписом ВК та новим ID приймається",
      rep.accepted and rep.decrypt_ok and rep.format_ok and rep.signature_ok and rep.id_unique)
check("ВК правильно розшифрувала бюлетень та обчислила H == Hc",
      rep.text == voters[0].signed[0][0] and rep.hash_from_text == rep.hash_from_signature)

print("\n=== 13. Негативні сценарії подання голосів ===")
before = commission.tally().accepted_total
rep = commission.receive_ballot(msg)
check("NEGATIVE: повторне надсилання того самого повідомлення відхилено (ID вже використано)",
      not rep.accepted and rep.signature_ok is True and rep.id_unique is False)

rep = commission.receive_ballot(voters[0].cast(2, pub))
check("NEGATIVE: другий бюлетень з того самого підписаного набору відхилено (повторний ID)",
      not rep.accepted and rep.signature_ok is True and rep.id_unique is False)
check("до підрахунку потрапив лише перший бюлетень, виборця №1 зараховано за кандидата №1",
      commission.accepted[parse_ballot(voters[0].signed[0][0])[0]][2] == 1
      and commission.tally().accepted_total == before)

fake = random.Random(1).randrange(2, pub[1])
t1, s1 = voters[1].signed[0]
rep = commission.receive_ballot(build_ballot_message(t1, fake, pub))
check("NEGATIVE: бюлетень з довільним (підробленим) підписом відхилено (H ≠ Hc)",
      not rep.accepted and rep.signature_ok is False
      and rep.hash_from_text != rep.hash_from_signature)
check("NEGATIVE: перевірка ID після недійсного підпису не виконувалась і ID не «спалено»",
      rep.id_unique is None
      and parse_ballot(t1)[0] not in commission.accepted)

(t_a, s_a), (t_b, s_b) = voters[2].signed
rep = commission.receive_ballot(build_ballot_message(t_b, s_a, pub))
check("NEGATIVE: підпис від бюлетеня за кандидата №1 не підходить до бюлетеня №2 (зміна вибору)",
      not rep.accepted and rep.signature_ok is False)
other_id = parse_ballot(t_a)[0] + 1
rep = commission.receive_ballot(build_ballot_message(ballot_text(other_id, 1), s_a, pub))
check("NEGATIVE: зміна ID у підписаному бюлетені робить підпис недійсним",
      not rep.accepted and rep.signature_ok is False)
rep = commission.receive_ballot(build_ballot_message(ballot_text(ID_LOW + 12345, 1), fake, pub))
check("NEGATIVE: самостійно сформований бюлетень без підпису ВК відхилено",
      not rep.accepted and rep.signature_ok is False)

stranger = ElectionCommission(CANDIDATES, random.Random(999))
rep = commission.receive_ballot(voters[3].cast(1, stranger.public_key))
check("NEGATIVE: повідомлення, зашифроване не ключем ВК, не розшифровується",
      not rep.accepted and rep.decrypt_ok is False)
rep = commission.receive_ballot(build_ballot_message("Кандидат №1", fake, pub))
check("NEGATIVE: бюлетень без ID (некоректний формат) відхилено до перевірки підпису",
      not rep.accepted and rep.format_ok is False and rep.signature_ok is None)
check("жодна з відмов не змінила кількість прийнятих бюлетенів",
      commission.tally().accepted_total == before)
check("відмови враховано у лічильнику відхилених (8)", commission.rejected_total == 8)

print("\n=== 14. Решта виборців голосують, підрахунок і публікація (крок 14) ===")
for voter, choice in zip(voters[1:], [2, 1, 1, 2]):
    rep = commission.receive_ballot(voter.cast(choice, pub))
    assert rep.accepted, rep.reason
result = commission.tally()
check("прийнято 5 бюлетенів, відхилено 8 повідомлень",
      result.accepted_total == 5 and result.rejected_total == 8)
check("підраховано 3 голоси за №1 та 2 за №2", result.counts == {1: 3, 2: 2})
check("статус: є переможець №1",
      result.status == "winner" and result.leaders == [1] and result.spoiled == 0)

published = commission.publish()
check("опубліковано 5 записів, відсортованих за ID",
      len(published) == 5
      and [e.ballot_id for e in published] == sorted(e.ballot_id for e in published))
check("у публікації немає жодного ПІБ", not any(n in repr(published) for n in NAMES))
check("будь-хто може перевірити всі підписи ВК у списку", verify_published(published, pub))
found = [v.verify_in_published(published) for v in voters[1:]]
check("кожен виборець знаходить свій ID, і його голос записано правильно",
      all(f and all(is_found and same for _, is_found, same in f) for f in found))
check("для виборця №1 перший голос збігається, повторний (відхилений) - ні",
      voters[0].verify_in_published(published)[0][1:] == (True, True)
      and voters[0].verify_in_published(published)[1][1:] == (True, False))

forged = list(published)
k = [e.ballot_id for e in forged].index(parse_ballot(voters[3].signed[0][0])[0])
flipped = ballot_text(forged[k].ballot_id, 2 if parse_ballot(forged[k].text)[1] == 1 else 1)
forged[k] = replace(forged[k], text=flipped)
check("ВК змінила чийсь голос у списку - підпис не збігається, публікація не проходить перевірку",
      not verify_published(forged, pub))
check("виборець, чий голос змінено, бачить розбіжність у своєму записі",
      voters[3].verify_in_published(forged)[0][1:] == (True, False))
dropped = [e for i, e in enumerate(published) if i != k]
check("ВК вилучила чийсь голос зі списку - виборець не знаходить свій ID",
      voters[3].verify_in_published(dropped)[0][1:] == (False, False))

print("\n=== 14б. Підробка голосу без підпису ВК (регресія) ===")
world, (honest, *_), _, wrng = make_world(seed=2027)
wpub = world.public_key
issue_signed_set(world, honest, wrng)
real_text, real_signature = honest.signed[0]
check("причина проблеми: шифрування дійсного підпису ключем ВК дає саме хеш бюлетеня (S^e = H)",
      encrypt_int(real_signature, wpub) == square_hash(real_text, wpub[1]))
attacks = []
for k in range(3):
    forged_text = ballot_text(3 * 10**18 + k, 1 + k % 2)
    h = square_hash(forged_text, wpub[1])
    attacks.append(world.receive_ballot(
        BallotMessage(blocks=encrypt_text(f"{forged_text}{SIGNATURE_SEPARATOR}{h}", wpub))))
check("NEGATIVE: хеш бюлетеня замість підпису ВК (підробка без підпису) відхиляється - 3 спроби",
      all(not r.accepted and r.signature_ok is False for r in attacks))
check("NEGATIVE: підробка не дала жодного прийнятого голосу",
      world.tally().accepted_total == 0)
forged_text = ballot_text(4 * 10**18, 1)
plain_attempts = {
    "підпис відсутній у повідомленні": forged_text,
    "підпис = 0": f"{forged_text}{SIGNATURE_SEPARATOR}0",
    "підпис не з цифр": f"{forged_text}{SIGNATURE_SEPARATOR}abc",
    "підпис з нулем попереду": f"{forged_text}{SIGNATURE_SEPARATOR}0123",
    "підпис, більший за модуль n": f"{forged_text}{SIGNATURE_SEPARATOR}{wpub[1] + 5}",
}
for label, plaintext in plain_attempts.items():
    r = world.receive_ballot(BallotMessage(blocks=encrypt_text(plaintext, wpub)))
    check(f"NEGATIVE: {label} - відхилено", not r.accepted)
check("жодна зі спроб підробки не змінила кількість прийнятих бюлетенів",
      world.tally().accepted_total == 0)
check("після спроб підробки чесний виборець голосує успішно",
      world.receive_ballot(honest.cast(1, wpub)).accepted)

print("\n=== 15. Анонімність: ВК не може зв'язати голос з виборцем ===")
seen_by_commission = set()
for r, v in zip(results, voters):
    seen_by_commission.update(r.reveal.signatures)
    seen_by_commission.update(x for s in v.sets for x in [m.h_masked for m in s.masked])
n = pub[1]
accepted_values = set()
for text, signature, _ in commission.accepted.values():
    accepted_values.add(square_hash(text, n))
    accepted_values.add(signature)
check("значення, які ВК бачила при видачі підписів (H', S'), не збігаються з H та S жодного голосу",
      not (seen_by_commission & accepted_values))
revealed_ids = {c.ballot_id for r in results for c in r.reveal.set_checks}
check("ID поданих голосів ВК ніколи не бачила під час розкриття наборів",
      not (revealed_ids & set(commission.accepted)))
check("ВК бачила ID лише розкритих наборів (45 ID для 5 виборців)", len(revealed_ids) == 45)
check("у прийнятих записах ВК немає імен виборців",
      not any(name in repr(commission.accepted) for name in NAMES))

print("\n=== 16. Підрахунок: рівномірний розподіл та відсутність голосів ===")
world, wvoters, _, wrng = make_world(seed=9)
for v in wvoters:
    issue_signed_set(world, v, wrng)
for v, choice in zip(wvoters[:4], [1, 2, 1, 2]):
    world.receive_ballot(v.cast(choice, world.public_key))
res_tie = world.tally()
check("один виборець утримався, голоси 2 : 2 - рівномірний розподіл",
      res_tie.status == "tie" and res_tie.leaders == [1, 2] and res_tie.counts == {1: 2, 2: 2})
world, _, _, _ = make_world(seed=10)
res_none = world.tally()
check("без голосів - статус no_votes, лічильники нульові",
      res_none.status == "no_votes" and res_none.counts == {1: 0, 2: 0})
check("порожній список публікується та проходить перевірку",
      world.publish() == [] and verify_published([], world.public_key))

print(f"\nРезультат: пройдено {passed}, провалено {failed}")
sys.exit(1 if failed else 0)
