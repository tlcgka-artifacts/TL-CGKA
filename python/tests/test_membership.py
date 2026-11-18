import copy
import unittest
from unittest.mock import patch
from tlcgka import crypto as c, gua, refresh, ubkem
from tlcgka.codec import ProtocolError, pack, unpack
from tlcgka.tl import Group
from tlcgka.membership import Membership
from tlcgka.driver import round_update


class DynamicUB(unittest.TestCase):
    def test_add_remove_fork_and_update_paths(self):
        for size in [1, 2, 3, 7, 8, 15, 16, 31]:
            tree, initial = ubkem.gen(range(size))
            paths = dict(enumerate(initial))
            for step in range(6):
                target = size + step
                tree, new, wire = ubkem.add(tree, target)
                paths = {i: ubkem.proc(p, wire) for i, p in paths.items()}
                paths[target] = new
                u, ct = ubkem.enc(tree)
                tree, key = ubkem.fin(u, step)
                for i, p in list(paths.items()):
                    paths[i], recovered = ubkem.dec(p, step, ct)
                    self.assertEqual(key, recovered)
                    for node, sk in zip(ubkem.path(paths[i].leaf), paths[i].private):
                        self.assertEqual(tree.public[node], c.nike_public(sk))
                removed = min(paths)
                old = paths.pop(removed)
                tree, wire = ubkem.rmv(tree, removed)
                with self.assertRaises(ProtocolError):
                    ubkem.proc(old, wire)
                paths = {i: ubkem.proc(p, wire) for i, p in paths.items()}
                a, b, fork = ubkem.fork(tree)
                forked = {i: ubkem.proc_fork(p, fork) for i, p in paths.items()}
                for branch, side in [(a, 0), (b, 1)]:
                    u, ct = ubkem.enc(branch)
                    _, key = ubkem.fin(u, (step, side))
                    for pair in forked.values():
                        self.assertEqual(ubkem.dec(pair[side], (step, side), ct)[1], key)
                for i, p in paths.items():
                    for node, sk in zip(ubkem.path(p.leaf), p.private):
                        self.assertEqual(tree.public[node], c.nike_public(sk))


class DynamicGUA(unittest.TestCase):
    def test_single_public_key_message_and_refresh_formula(self):
        states = gua.init(b"single-key", (0, 1, 2))
        old = refresh.anchor(states[0])
        join_sk, e, eta = c.scalar(), 17, bytes(range(32))
        # e, confirmation-signature randomness, outer-auth randomness.
        with patch.object(refresh.c, "scalar", side_effect=[e, 19, 23]), \
             patch.object(refresh.os, "urandom", return_value=eta):
            wire, staged = refresh.change(states[0], "A", 3, c.base(join_sk), b"ctx")
        payload, _ = unpack(wire)
        prior, issuer, op, target, target_pk, P, masks, signature, _ = payload
        self.assertEqual(P, c.base(e))
        self.assertEqual(prior, refresh.anchor_tag(old))
        self.assertIsInstance(prior[2], bytes)
        self.assertEqual(len(prior[2]), 32)
        Lprime = dict(states[0].roster)
        Lprime[3], Lprime[0] = target_pk, P
        Lprime = tuple(sorted(Lprime.items()))
        expected_m = c.digest("refresh-rat", 1, eta, c.digest("refresh-roster", Lprime))
        expected_sk = e * c.hscalar("refresh-ref", 0, eta) % c.ORDER
        self.assertEqual(staged.m, expected_m)
        self.assertEqual(staged.sk, expected_sk)
        self.assertEqual(staged.pk, c.base(expected_sk))
        self.assertEqual(dict(staged.roster)[0], staged.pk)
        self.assertNotEqual(staged.pk, P)
        self.assertEqual(staged.key, c.digest("key", expected_m, staged.pk))
        for i in (1, 2, 3):
            old_sk = join_sk if i == 3 else states[i].sk
            recovered = refresh.recover(old, i, old_sk, wire, b"ctx")
            self.assertEqual(recovered.sk, old_sk * c.hscalar("refresh-ref", i, eta) % c.ORDER)
            self.assertEqual(dict(staged.roster)[i], c.base(recovered.sk))
            self.assertEqual(recovered.roster, staged.roster)
            self.assertEqual(recovered.key, staged.key)
        # The control carries target_pk and P, not either complete public roster.
        for _, pk in states[0].roster:
            self.assertNotIn(pk, wire)

    def test_refresh_context_tamper_and_signed_malformed_control(self):
        states = gua.init(b"refresh-checks", (0, 1, 2))
        old = refresh.anchor(states[0])
        wire, _ = refresh.change(states[0], "A", 3, c.base(c.scalar()), b"ctx")
        with self.assertRaises(ProtocolError):
            refresh.recover(old, 1, states[1].sk, wire, b"wrong")
        payload, auth = unpack(wire)
        altered = list(payload)
        altered[5] = c.base(c.scalar())
        with self.assertRaises(ProtocolError):
            refresh.recover(old, 1, states[1].sk, pack((tuple(altered), auth)), b"ctx")
        altered = list(payload)
        altered[6] = tuple((i, value[:-1]) for i, value in payload[6])
        altered = tuple(altered)
        signed = pack((altered, c.sign(states[0].sk, c.digest("GUA.Change", altered))))
        with self.assertRaises(ProtocolError):
            refresh.recover(old, 1, states[1].sk, signed, b"ctx")

    def test_refresh_add_remove_and_old_state_exclusion(self):
        states = gua.init(b"dynamic", (0, 1, 2))
        new_sk = c.scalar()
        old = refresh.anchor(states[0])
        wire, staged = refresh.change(states[0], "A", 3, c.base(new_sk), b"add")
        states = {i: refresh.recover(old, i, states[i].sk if i != 3 else new_sk, wire, b"add") for i in (1, 2, 3)}
        states[0] = staged
        self.assertEqual(len({s.key for s in states.values()}), 1)
        old, revoked = refresh.anchor(staged), states.pop(2)
        wire, staged = refresh.change(states[0], "R", 2, c.base(revoked.sk), b"remove")
        with self.assertRaises(ProtocolError):
            refresh.recover(old, 2, revoked.sk, wire, b"remove")
        for i in (1, 3):
            states[i] = refresh.recover(old, i, states[i].sk, wire, b"remove")
        states[0] = staged
        rho = c.hgroup("test", b"secret")
        _, ciphertext = gua.enc(staged, rho)
        self.assertNotEqual(gua.dec(revoked, ciphertext), rho)
        self.assertTrue(all(gua.dec(st, ciphertext) == rho for st in states.values()))


class CoreMembership(unittest.TestCase):
    def test_change_then_handoff(self):
        group = Group.balanced(16, 2, 2, strict_i_equals_f=False)
        driver = Membership(group)
        driver.update()
        driver.change(0, "A", 16)
        driver.drain()
        for _ in range(5):
            round_update(group, handoff=True)
        driver.change(0, "R", 1)
        driver.drain()
        for _ in range(5):
            round_update(group, handoff=True)

    def test_join_leave_and_every_source_contributes(self):
        for n in (8, 16, 32, 64):
            g = Group.balanced(n, 2, 2)
            driver = Membership(g)
            driver.update()
            previous = next(iter(g.cores.values())).key
            driver.change(0, "A", n)
            self.assertIsNone(g.cores[n].key)
            with self.assertRaises(ProtocolError):
                driver.update()
            driver.drain()
            for _ in range(4):
                driver.update()
            revoked = copy.deepcopy(g.cores[1])
            driver.change(0, "R", 1)
            driver.drain()
            for _ in range(4):
                trace = driver.update()
                key = next(iter(g.cores.values())).key
                self.assertNotEqual(key, previous)
                x, envelope, sealed, signature = unpack(trace.final_messages[0])
                header, epoch, ct, alpha, _ = envelope
                source = header[2]
                if source in revoked.sources:
                    _, old_root = ubkem.dec(revoked.sources[source].path, (header, ct), ct)
                    with self.assertRaises(ProtocolError):
                        c.open_seal(c.kdf("subgroup-envelope", old_root, (header, ct)), sealed, envelope)

    def test_wrong_context_replay_and_tamper_do_not_install(self):
        g = Group.balanced(8, 2, 2)
        driver = Membership(g)
        skg, skl = c.scalar(), c.scalar()
        oldg, oldl = refresh.anchor(g.cores[0].global_state), refresh.anchor(g.cores[0].local)
        before = g.ordinary[2].record()
        wire, _ = driver.change_core(0, "A", 8, c.base(skg), c.base(skl))
        body, authg, authl = unpack(wire)
        bad = pack((body, authg, (authl[0], bytes(32))))
        with self.assertRaises(ProtocolError):
            driver._process(2, bad, oldg, oldl)
        driver.version += 1
        with self.assertRaises(ProtocolError):
            driver._process(2, wire, oldg, oldl)
        self.assertEqual(before, g.ordinary[2].record())




class OrdinaryMembership(unittest.TestCase):
    def test_join_remove_rejoin_and_core_rotation(self):
        g = Group.balanced(16, 2, 2)
        m = Membership(g)
        m.update()
        for op in ("A", "R", "A"):
            previous = g.cores[0].history, g.cores[0].epoch
            nonce_pool = dict(g.nonce_service.clients[0].pool)
            roster = g.cores[0].local.roster
            m.change_ordinary(0, op, 16)
            if op == "A":
                self.assertIsNone(g.ordinary[16].key)
            else:
                self.assertNotIn(16, m.channels.keys)
            self.assertEqual((g.cores[0].history, g.cores[0].epoch), previous)
            self.assertEqual(g.cores[0].local.roster, roster)
            self.assertEqual(g.nonce_service.clients[0].pool, nonce_pool)
            with self.assertRaises(ProtocolError):
                m.update()
            m.drain()
            for _ in range(2):
                m.update()
        m.change(0, "A", 17)
        m.drain()
        for i, src in g.ordinary[16].sources.items():
            self.assertEqual(src.verification_key, dict(g.cores[0].local.roster)[i])
        m.update()

    def test_single_core_subgroup_and_invalid_removals(self):
        g = Group.balanced(4, 2, 1)
        m = Membership(g)
        for target in (0, 1, 3):
            with self.assertRaises(ProtocolError):
                m.change_ordinary(0, "R", target)
        m.change_ordinary(0, "A", 4)
        m.update()
        m.change_ordinary(0, "R", 1)
        m.update()


if __name__ == "__main__":
    unittest.main()
