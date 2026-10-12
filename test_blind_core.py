import random
import sys

from rsa_core import (
    keypair_from_primes, generate_keypair, mod_inverse,
    square_hash, sign, verify, verify_detailed,
    encrypt_int, decrypt_int,
)
from blind_core import (
    gcd, is_valid_mask, random_mask,
    blind, blind_sign, unblind, mask_hash, check_masked_hash,
)

try:
    sys.stdout.reconfigure(encoding="utf-8")
except AttributeError:
    pass

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


def raises(func, *args):
    try:
        func(*args)
    except ValueError:
        return True
    return False


print("=== 1. Навчальний приклад (p=61, q=53, e=17, d=2753; H=1234, r=7) ===")
kp = keypair_from_primes(61, 53, 17)
check("n = 3233, d = 2753", kp.n == 3233 and kp.d == 2753)
check("НСД(7, 3233) = 1", gcd(7, 3233) == 1)
check("r^(-1) = 462, r * r^(-1) mod n = 1",
      mod_inverse(7, 3233) == 462 and (7 * 462) % 3233 == 1)
h_masked = blind(1234, 7, kp.public)
check("маскування: H' = 1234 * 7^17 mod 3233 = 714", h_masked == 714)
s_masked = blind_sign(h_masked, kp.private)
check("сліпий підпис: S' = 714^2753 mod 3233 = 885", s_masked == 885)
s = unblind(s_masked, 7, kp.n)
check("зняття маскування: S = 885 * 462 mod 3233 = 1512", s == 1512)
check("S збігається зі звичайним ЕЦП на H (1234^d mod n)", s == pow(1234, kp.d, kp.n))
check("Hc = S^e mod n = 1234 = H (підпис дійсний)", pow(s, kp.e, kp.n) == 1234)

print("\n=== 2. Допустимість множника маскування ===")
check("r = 7 допустимий", is_valid_mask(7, 3233))
check("r = 61 (дільник n) недопустимий", not is_valid_mask(61, 3233))
check("r = 53 (дільник n) недопустимий", not is_valid_mask(53, 3233))
check("r = 122 (кратне 61) недопустимий", not is_valid_mask(122, 3233))
check("r = 0 і r = 1 недопустимі (не маскують хеш)",
      not is_valid_mask(0, 3233) and not is_valid_mask(1, 3233))
check("r = n і r > n недопустимі",
      not is_valid_mask(3233, 3233) and not is_valid_mask(3234, 3233))
check("blind() відхиляє r, не взаємно простий з n",
      raises(blind, 1234, 61, kp.public))
check("unblind() відхиляє r, не взаємно простий з n",
      raises(unblind, 885, 53, kp.n))
check("blind() відхиляє хеш поза діапазоном",
      raises(blind, 3233, 7, kp.public) and raises(blind, -1, 7, kp.public))
check("blind_sign() відхиляє значення поза діапазоном",
      raises(blind_sign, 3233, kp.private) and raises(blind_sign, -5, kp.private))
rng = random.Random(3)
masks = [random_mask(3233, rng) for _ in range(500)]
check("random_mask: 500 множників, усі допустимі (взаємно прості з n)",
      all(is_valid_mask(r, 3233) for r in masks))
check("random_mask дає різні значення", len(set(masks)) > 100)

print("\n=== 3. Ключі ЕЦП ВК (256 біт) і повний цикл на реальному бюлетені ===")
rng = random.Random(2026)
vk = generate_keypair(128, rng)
ballot = "ID=7283610958472016351; Кандидат №1"
h = square_hash(ballot, vk.n)
item = mask_hash(h, vk.public, rng)
check("множник маскування r взаємно простий з n ВК", gcd(item.r, vk.n) == 1)
check("H' = H * r^e mod n (обчислено незалежно)",
      item.h_masked == (h * pow(item.r, vk.e, vk.n)) % vk.n)
check("замаскований хеш H' не збігається з хешем H", item.h_masked != h)
s_masked = blind_sign(item.h_masked, vk.private)
s = unblind(s_masked, item.r, vk.n)
check("POSITIVE: після зняття маскування ЕЦП дійсний (H == Hc)",
      verify_detailed(ballot, s, vk.public)[2])
check("розкритий ЕЦП збігається зі звичайним ЕЦП ВК на цьому бюлетені",
      s == sign(ballot, vk.private))
check("ЕЦП менший за модуль ВК (шифрується одним блоком)", s < vk.n)
check("підпис переживає шифрування відкритим ключем ВК і розшифрування",
      decrypt_int(encrypt_int(s, vk.public), vk.private) == s)

print("\n=== 4. Негативні сценарії підпису ===")
check("NEGATIVE: сліпий підпис S' без зняття маскування недійсний",
      not verify(ballot, s_masked, vk.public))
wrong_r = random_mask(vk.n, rng)
check("NEGATIVE: зняття маскування з чужим множником дає недійсний ЕЦП",
      not verify(ballot, unblind(s_masked, wrong_r, vk.n), vk.public))
check("NEGATIVE: ЕЦП не підходить до бюлетеня з іншим кандидатом",
      not verify("ID=7283610958472016351; Кандидат №2", s, vk.public))
check("NEGATIVE: ЕЦП не підходить до бюлетеня з іншим ID",
      not verify("ID=7283610958472016352; Кандидат №1", s, vk.public))
check("NEGATIVE: змінений ЕЦП недійсний",
      not verify(ballot, (s + 1) % vk.n, vk.public))
check("NEGATIVE: ЕЦП поза діапазоном відхиляється",
      not verify(ballot, vk.n + 5, vk.public))
other = generate_keypair(128, rng)
check("NEGATIVE: ЕЦП не перевіряється ключем іншої комісії",
      not verify(ballot, s, other.public))

print("\n=== 5. Перевірка ВК розкритого набору (крок 8 протоколу) ===")
check("POSITIVE: правильні H і r відповідають замаскованому хешу",
      check_masked_hash(h, item.r, item.h_masked, vk.public))
check("NEGATIVE: інший множник r не відповідає замаскованому хешу",
      not check_masked_hash(h, wrong_r, item.h_masked, vk.public))
changed_h = square_hash("ID=7283610958472016351; Кандидат №2", vk.n)
check("NEGATIVE: інший бюлетень (інший хеш) не відповідає замаскованому хешу",
      not check_masked_hash(changed_h, item.r, item.h_masked, vk.public))
check("NEGATIVE: r, не взаємно простий з n, відхиляється без винятку",
      not check_masked_hash(h, vk.p, item.h_masked, vk.public))
check("NEGATIVE: хеш поза діапазоном відхиляється без винятку",
      not check_masked_hash(vk.n + 1, item.r, item.h_masked, vk.public))

print("\n=== 6. Сліпота: ВК не може зв'язати H' з бюлетенем ===")
h1 = square_hash("ID=111; Кандидат №1", vk.n)
h2 = square_hash("ID=222; Кандидат №2", vk.n)
item1 = mask_hash(h1, vk.public, rng)
s1_masked = blind_sign(item1.h_masked, vk.private)
r2 = pow((item1.h_masked * mod_inverse(h2, vk.n)) % vk.n, vk.d, vk.n)
check("існує множник r2, за яким H' отримано з іншого хешу H2",
      is_valid_mask(r2, vk.n) and check_masked_hash(h2, r2, item1.h_masked, vk.public))
check("той самий сліпий підпис S' після зняття r2 дає дійсний ЕЦП на H2",
      verify("ID=222; Кандидат №2", unblind(s1_masked, r2, vk.n), vk.public))
check("з r1 той самий S' дає ЕЦП на H1 (а не на H2)",
      verify("ID=111; Кандидат №1", unblind(s1_masked, item1.r, vk.n), vk.public)
      and not verify("ID=222; Кандидат №2", unblind(s1_masked, item1.r, vk.n), vk.public))
a = mask_hash(h1, vk.public, rng)
b = mask_hash(h1, vk.public, rng)
check("один хеш з різними множниками дає різні замасковані хеші",
      a.r != b.r and a.h_masked != b.h_masked)

print("\n=== 7. Масова перевірка та крайні випадки ===")
rng = random.Random(77)
all_ok = True
for _ in range(300):
    text = f"ID={rng.getrandbits(64)}; Кандидат №{rng.choice((1, 2))}"
    hh = square_hash(text, vk.n)
    it = mask_hash(hh, vk.public, rng)
    ss = unblind(blind_sign(it.h_masked, vk.private), it.r, vk.n)
    all_ok = all_ok and verify(text, ss, vk.public) and check_masked_hash(
        hh, it.r, it.h_masked, vk.public)
check("300 випадкових бюлетенів: сліпий ЕЦП завжди дійсний", all_ok)
rng = random.Random(5)
keys_ok = True
for _ in range(20):
    k = generate_keypair(64, rng)
    text = f"ID={rng.getrandbits(64)}; Кандидат №1"
    hh = square_hash(text, k.n)
    it = mask_hash(hh, k.public, rng)
    ss = unblind(blind_sign(it.h_masked, k.private), it.r, k.n)
    keys_ok = keys_ok and verify(text, ss, k.public)
check("20 різних пар ключів ВК (по 64-бітні прості): сліпий ЕЦП дійсний", keys_ok)
check("крайній випадок H = 0: підпис дійсний",
      unblind(blind_sign(blind(0, 7, kp.public), kp.private), 7, kp.n) == 0)
check("крайній випадок H = n - 1: підпис дійсний",
      pow(unblind(blind_sign(blind(3232, 7, kp.public), kp.private), 7, kp.n),
          kp.e, kp.n) == 3232)

print(f"\nРезультат: пройдено {passed}, провалено {failed}")
sys.exit(1 if failed else 0)
