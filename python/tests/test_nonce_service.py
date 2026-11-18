import unittest
from tlcgka import crypto as c
from tlcgka.codec import ProtocolError, pack, unpack
from tlcgka.nonce_service import Session, SERVER
from tlcgka.driver import Trace, prepare_nonces, round_update
from tlcgka.tl import Group
from tlcgka.membership import Membership


class NonceServiceTests(unittest.TestCase):
    def test_preprocessing_private_secrets_and_single_use(self):
        s = Session(b'group', (0, 1, 2), window=2)
        t = Trace()
        s.preprocess(0, b'roster', t)
        self.assertEqual(len(s.server.registry), 6)
        self.assertFalse(hasattr(s.server, 'clients'))
        expected = c.total(s.clients[i].pool[1].R for i in (0, 2))
        binding = (b'group', 0, 1, ((0, 0), (1, 2)), (0, 2), b'transcript')
        result = s.aggregate(binding, t)
        self.assertTrue(all(R == expected for R, _ in result.values()))
        self.assertIsNone(result[1][1])
        n = result[0][1]
        n.consume()
        with self.assertRaises(ProtocolError): n.consume()
        self.assertTrue(all(1 not in client.pool for client in s.clients.values()))
        with self.assertRaises(ProtocolError): s.aggregate(binding, t)
        self.assertTrue(all(e == 2 for _, e in s.server.registry))

    def test_secure_channel_tamper_and_replay(self):
        s = Session(b'group', (0,))
        endpoint, peer = s.clients[0].endpoint, s.server.endpoints[0]
        wire = endpoint.send(('hello',))
        seq, data = unpack(wire)
        with self.assertRaises(ProtocolError):
            peer.receive(pack((seq, data[:-1] + bytes([data[-1] ^ 1]))))
        self.assertEqual(peer.receive(wire), ('hello',))
        with self.assertRaises(ProtocolError): peer.receive(wire)

    def test_commit_barrier_and_bad_opening(self):
        s = Session(b'group', (0, 1), window=2)
        context = (b'group', 0, 1, b'roster', 0, 2)
        s.server.begin(context, (0, 1))
        for i in (0, 1): s.server.commit(i, s.clients[i].prepare(context))
        with self.assertRaises(ProtocolError): s.server.commit(0, s.clients[0].prepare(context))
        s.server.freeze()
        s.clients[0].pool[1].salt = bytes(32)
        with self.assertRaises(ProtocolError): s.server.open(0, s.clients[0].open())
        self.assertFalse(s.server.registry)

    def test_windows_refill_and_membership_invalidation(self):
        g = Group.balanced(16, 2, 2)
        g.nonce_service.window = 2
        first = round_update(g)
        self.assertIsNotNone(first.preprocessing)
        self.assertGreater(first.local_cpu_ns, 0)
        self.assertTrue(any(source == SERVER for _, source, _, _ in first.messages))
        self.assertFalse(any(label in ('nonce_commit', 'nonce_open') for label, _, _, _ in first.messages))
        self.assertIsNone(round_update(g).preprocessing)
        self.assertIsNotNone(round_update(g).preprocessing)
        old = g.nonce_service.context
        saved = [n for client in g.nonce_service.clients.values() for n in client.pool.values()]
        m = Membership(g)
        m.change(0, 'A', 16)
        self.assertTrue(all(n.secret is None for n in saved))
        self.assertFalse(g.nonce_service.ready(5))
        m.drain()
        update = m.update()
        self.assertIsNotNone(update.preprocessing)
        self.assertNotEqual(old, g.nonce_service.context)
        m.change(0, 'R', 1)
        self.assertNotIn(1, g.nonce_service.clients)
        m.drain(); m.update()

    def test_invalid_rounds_and_identity_aggregate(self):
        def ready():
            s = Session(b'group', (0, 1), window=2)
            s.preprocess(0, b'roster', Trace())
            return s
        base = (b'group', 0, 1, ((0, 0),), (0,), b'transcript')
        for index, value in ((0,b'wrong'),(1,1),(2,3),(4,()),(4,(0,0)),(4,(9,))):
            s = ready()
            b = list(base); b[index] = value; b = tuple(b)
            wire = s.clients[0].endpoint.send((s.context,b))
            with self.assertRaises(ProtocolError): s.server.update(0,wire)
            self.assertEqual(s.server.last_epoch, 0)
        s = ready()
        s.server.registry[0,1] = c.IDENTITY
        wire = s.clients[0].endpoint.send((s.context,base))
        with self.assertRaises(ProtocolError): s.server.update(0,wire)

    def test_wrong_reply_binding_and_skipped_slots(self):
        s = Session(b'group', (0, 1), window=3)
        s.preprocess(0, b'roster', Trace())
        binding = (b'group',0,2,((0,0),),(0,),b'transcript')
        saved = s.clients[0].pool[1]
        s.aggregate(binding,Trace())
        self.assertIsNone(saved.secret)
        self.assertEqual(set(s.clients[0].pool),{3})
        wire=s.server.endpoints[0].send((s.context,(*binding[:-1],b'wrong'),c.base(c.scalar())))
        with self.assertRaises(ProtocolError): s.clients[0].accept(wire,binding,True)

    def test_cached_share_rejects_changed_server_nonce(self):
        g = Group.balanced(16,2,2)
        prepare_nonces(g)
        A, B = ((0,0),(1,8)), (0,8)
        for core in g.cores.values(): core.configure_round(A,B)
        packages = [g.cores[i].prepare() for _,i in A]
        qgs = [qg for _,qg in packages]
        binding = (g.gid,0,1,A,B,c.digest('nonce-round',tuple(qgs)))
        prepared = g.nonce_service.aggregate(binding,Trace())
        a = g.cores[0]
        R, a.nonce = prepared[0]
        wire = a.share(packages[0][0],qgs,R)
        self.assertEqual(a.share(packages[0][0],qgs,R),wire)
        with self.assertRaises(ProtocolError):
            a.share(packages[0][0],qgs,c.base(c.scalar()))


if __name__ == '__main__': unittest.main()
