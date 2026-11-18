"""Authenticated history across group updates and core membership changes."""
import copy
import unittest
from tlcgka import crypto as c, refresh
from tlcgka.codec import ProtocolError, pack, unpack
from tlcgka.tl import Group
from tlcgka.driver import round_update, prepare_nonces
from tlcgka.membership import Membership


class GroupHistoryTests(unittest.TestCase):
    def test_history_agreement_and_ordered_catchup(self):
        g = Group.balanced(16, 2, 2)
        old = bytes(32)
        backlog = []
        for _ in range(4):
            trace = round_update(g, deliver=False)
            history = next(iter(g.cores.values())).history
            self.assertNotEqual(old, history)
            self.assertTrue(all(x.history == history for x in g.cores.values()))
            old = history
            backlog.append(trace.final_messages)
        for messages in backlog:
            for user in g.ordinary.values():
                user.receive(messages[user.subgroup])
        self.assertEqual({x.history for x in (*g.cores.values(), *g.ordinary.values())}, {old})

    def test_wrong_history_rejects_otherwise_valid_broadcast_atomically(self):
        g = Group.balanced(8, 2, 2)
        messages = round_update(g, deliver=False).final_messages
        user = next(iter(g.ordinary.values()))
        wrong = copy.deepcopy(user)
        wrong.history = b'\x01' * 32
        before = wrong.record()
        with self.assertRaises(ProtocolError):
            wrong.receive(messages[user.subgroup])
        self.assertEqual(wrong.record(), before)
        user.receive(messages[user.subgroup])
        self.assertEqual(user.history, g.cores[0].history)

    def test_membership_binds_history_and_joiner_inherits_it(self):
        g = Group.balanced(8, 2, 2)
        m = Membership(g)
        m.update()
        history = g.cores[0].history
        m.change(0, 'A', 8)
        self.assertEqual(g.cores[8].history, history)
        self.assertTrue(all(x.history == history for x in (*g.cores.values(), *g.ordinary.values())))
        m.drain()
        m.update()
        self.assertTrue(all(x.history == g.cores[0].history for x in (*g.cores.values(), *g.ordinary.values())))

    def test_changed_history_membership_control_does_not_install(self):
        g = Group.balanced(8, 2, 2)
        m = Membership(g)
        oldg, oldl = refresh.anchor(g.cores[0].global_state), refresh.anchor(g.cores[0].local)
        wire, _ = m.change_core(0, 'A', 8, c.base(c.scalar()), c.base(c.scalar()))
        body, ag, al = unpack(wire)
        h = (*body[0][:-1], b'\x01' * 32)
        changed = (h, *body[1:])
        # Even the genuine sponsor's signatures cannot move a receiver from
        # a different authenticated predecessor history.
        bad = pack((changed, c.sign(g.cores[0].global_state.sk, c.digest('ChangeCore', changed)),
                    c.sign(g.cores[0].local.sk, c.digest('ChangeCore', changed))))
        before = g.ordinary[2].record()
        with self.assertRaises(ProtocolError):
            m._process(2, bad, oldg, oldl)
        self.assertEqual(g.ordinary[2].record(), before)

    def test_change_core_uses_steps_one_to_three_only(self):
        g = Group.balanced(8, 2, 2)
        m = Membership(g)
        wire, _ = m.change_core(0, 'A', 8, c.base(c.scalar()), c.base(c.scalar()))
        body, global_auth, local_auth = unpack(wire)
        self.assertEqual(len(unpack(body[1])), 9)
        self.assertEqual(len(unpack(body[2])), 9)
        self.assertEqual(body[0][-1], g.cores[0].history)
        self.assertTrue(c.verify(dict(g.cores[0].global_state.roster)[0], c.digest('ChangeCore', body), global_auth))
        self.assertTrue(c.verify(dict(g.cores[0].local.roster)[0], c.digest('ChangeCore', body), local_auth))

    def test_multiple_confirmers_per_subgroup(self):
        g = Group.balanced(16, 2, 3, strict_i_equals_f=False)
        prepare_nonces(g)
        A, B = ((0, 0), (1, 8)), tuple(sorted(g.cores))
        for core in g.cores.values():
            core.configure_round(A, B)
        packages = [g.cores[i].prepare() for _, i in A]
        qgs = [qg for _, qg in packages]
        binding = (g.gid, 0, 1, A, B, c.digest('nonce-round', tuple(qgs)))
        from tlcgka.driver import Trace
        prepared = g.nonce_service.aggregate(binding, Trace())
        shares = []
        for i, core in g.cores.items():
            R, core.nonce = prepared[i]
            shares.append(core.share(packages[core.subgroup][0], qgs, R))
        messages = {}
        for i, core in g.cores.items():
            wire = core.commit(shares, send=i in (0, 8))
            if wire is not None:
                messages[core.subgroup] = wire
        for user in g.ordinary.values():
            user.receive(messages[user.subgroup])
        self.assertEqual(len({x.key for x in (*g.cores.values(), *g.ordinary.values())}), 1)
        self.assertEqual(len({x.history for x in (*g.cores.values(), *g.ordinary.values())}), 1)


if __name__ == '__main__':
    unittest.main()
