"""Commitment and nonce preprocessing over authenticated channels.

Clients retain secret nonces. The server stores commitments and public points.
Session routes messages between clients and the server."""
import os
from . import crypto as c, gua
from .codec import pack, unpack, require

SERVER = 'nonce-server'


class Endpoint:
    def __init__(self, key, sid, owner, peer):
        self.key, self.sid, self.owner, self.peer = key, sid, owner, peer
        self.tx = self.rx = 0

    def send(self, value):
        seq = self.tx
        wire = pack((seq, c.seal(self.key, pack(value), (self.sid, self.owner, self.peer, seq))))
        self.tx += 1
        return wire

    def receive(self, wire):
        seq, encrypted = unpack(wire)
        require(seq == self.rx, 'nonce channel replay/out-of-order record')
        value = unpack(c.open_seal(self.key, encrypted, (self.sid, self.peer, self.owner, seq)))
        self.rx += 1
        return value


class Client:
    def __init__(self, member, endpoint):
        self.member, self.endpoint = member, endpoint
        self.pool = {}
        self.context = None

    def prepare(self, context):
        self.clear()
        self.context = context
        base, window = context[-2:]
        entries = []
        for epoch in range(base + 1, base + window + 1):
            nonce = gua.Nonce.prepare((context, epoch), self.member)
            self.pool[epoch] = nonce
            entries.append((epoch, nonce.commitment()[1]))
        return self.endpoint.send(('commit', context, tuple(entries)))

    def open(self):
        return self.endpoint.send(('open', self.context,
                                   tuple((epoch, n.R, n.salt) for epoch, n in self.pool.items())))

    def accept(self, wire, binding, selected):
        context, received_binding, R = self.endpoint.receive(wire)
        require(context == self.context and received_binding == binding, 'nonce response context mismatch')
        c.point(R, True)
        epoch = binding[2]
        require(epoch in self.pool, 'missing/consumed client nonce')
        nonce = self.pool.pop(epoch)
        for stale in [e for e in self.pool if e < epoch]:
            self.pool.pop(stale).burn()
        if not selected:
            nonce.burn()
            nonce = None
        return R, nonce

    def clear(self):
        for n in self.pool.values():
            n.burn()
        self.pool.clear()


class Server:
    def __init__(self):
        self.endpoints = {}
        self.members = ()
        self.context = None
        self.commits = {}
        self.registry = {}
        self.opened = set()
        self.frozen = False
        self.last_epoch = -1

    def begin(self, context, members):
        self.context, self.members = context, tuple(members)
        self.commits, self.registry, self.opened = {}, {}, set()
        self.frozen = False
        self.last_epoch = context[-2]

    def commit(self, member, wire):
        kind, context, entries = self.endpoints[member].receive(wire)
        require(kind == 'commit' and context == self.context and member in self.members,
                'nonce commitment context mismatch')
        require(not self.frozen and member not in self.commits, 'duplicate/late commitment')
        base, window = context[-2:]
        require(tuple(e for e, _ in entries) == tuple(range(base + 1, base + window + 1)), 'wrong nonce window')
        require(all(isinstance(h, bytes) and len(h) == 32 for _, h in entries), 'invalid commitment')
        self.commits[member] = dict(entries)

    def freeze(self):
        require(set(self.commits) == set(self.members), 'missing nonce commitments')
        self.frozen = True

    def open(self, member, wire):
        kind, context, entries = self.endpoints[member].receive(wire)
        require(self.frozen and kind == 'open' and context == self.context, 'opening before commit barrier')
        require(member in self.members and member not in self.opened, 'duplicate/unknown opening')
        require(tuple(e for e, _, _ in entries) == tuple(self.commits[member]), 'wrong opening window')
        staged = {}
        for epoch, R, salt in entries:
            c.point(R, True)
            require(isinstance(salt, bytes) and len(salt) == 32, 'invalid opening salt')
            require(self.commits[member][epoch] == c.digest('nonce-commit', (context, epoch), member, R, salt),
                    'nonce commitment mismatch')
            staged[member, epoch] = R
        self.registry.update(staged)
        self.opened.add(member)

    def update(self, requester, wire):
        context, binding = self.endpoints[requester].receive(wire)
        gid, version, epoch, contributors, confirmers, transcript = binding
        require(context == self.context and (gid, version) == context[:2], 'wrong server round context')
        require(set(self.opened) == set(self.members), 'incomplete nonce preprocessing')
        require(confirmers and tuple(sorted(set(confirmers))) == confirmers and set(confirmers) <= set(self.members),
                'invalid confirmation set')
        require(requester in self.members and epoch > self.last_epoch, 'replayed nonce aggregation')
        require(all((i, epoch) in self.registry for i in confirmers), 'missing nonce slot')
        R = c.total(self.registry[i, epoch] for i in confirmers)
        require(R != c.IDENTITY, 'identity aggregate nonce')
        # Burn the entire epoch, including unused members, before returning.
        self.last_epoch = epoch
        self.registry = {key: value for key, value in self.registry.items() if key[1] > epoch}
        return R


class Session:
    def __init__(self, gid, members, window=16):
        require(window > 0, 'invalid preprocessing window')
        self.gid, self.version, self.window, self.batch = gid, 0, window, 0
        self.server, self.clients = Server(), {}
        self.context = None
        for i in members:
            self.register(i)

    def register(self, member):
        key, sid = os.urandom(32), os.urandom(24)
        self.clients[member] = Client(member, Endpoint(key, sid, member, SERVER))
        self.server.endpoints[member] = Endpoint(key, sid, SERVER, member)

    def reconfigure(self, members, trace):
        members = tuple(sorted(members))
        sponsor = min(set(self.clients) & set(members))
        new_version = self.version + 1
        wire = trace.timed('nonce_roster_send', sponsor, self.clients[sponsor].endpoint.send,
                           ('roster', self.gid, new_version, members))
        trace.sent('nonce_roster', sponsor, wire, (SERVER,))
        def install():
            value = self.server.endpoints[sponsor].receive(wire)
            require(value == ('roster', self.gid, new_version, members), 'nonce roster mismatch')
            self.server.context = None
            self.server.registry.clear()
            self.server.commits.clear()
        trace.timed('nonce_roster_install', SERVER, install)
        for i, client in self.clients.items():
            trace.timed('nonce_pool_invalidate', i, client.clear)
        for i in set(self.clients) - set(members):
            del self.clients[i]
            del self.server.endpoints[i]
        for i in set(members) - set(self.clients):
            trace.timed('nonce_channel_provision', i, self.register, i)
        self.version = new_version
        self.context = None

    def ready(self, epoch):
        return self.context is not None and all(epoch in client.pool for client in self.clients.values())

    def preprocess(self, base, roster_digest, trace):
        self.batch += 1
        self.context = (self.gid, self.version, self.batch, roster_digest, base, self.window)
        members = tuple(sorted(self.clients))
        trace.timed('nonce_batch_begin', SERVER, self.server.begin, self.context, members)
        for i in members:
            wire = trace.timed('nonce_precompute', i, self.clients[i].prepare, self.context)
            trace.sent('nonce_commit_upload', i, wire, (SERVER,))
            trace.timed('nonce_commit_register', SERVER, self.server.commit, i, wire)
        trace.timed('nonce_commit_barrier', SERVER, self.server.freeze)
        for i in members:
            wire = trace.timed('nonce_open_send', i, self.clients[i].open)
            trace.sent('nonce_open_upload', i, wire, (SERVER,))
            trace.timed('nonce_open_register', SERVER, self.server.open, i, wire)

    def aggregate(self, binding, trace):
        requester = binding[4][0]
        wire = trace.timed('nonce_request', requester, self.clients[requester].endpoint.send, (self.context, binding))
        trace.sent('nonce_request', requester, wire, (SERVER,))
        R = trace.timed('nonce_server_update', SERVER, self.server.update, requester, wire)
        result = {}
        for i, client in self.clients.items():
            wire = trace.timed('nonce_result_send', SERVER, self.server.endpoints[i].send, (self.context, binding, R))
            trace.sent('nonce_result', SERVER, wire, (i,))
            result[i] = trace.timed('nonce_result_receive', i, client.accept, wire, binding, i in binding[4])
        return result

    def storage(self):
        endpoint = lambda e: (e.key, e.sid, e.owner, e.peer, e.tx, e.rx)
        registry = tuple((i, e, R) for (i, e), R in sorted(self.server.registry.items()))
        return dict(server_registry_bytes=len(pack(registry)),
                    server_state_bytes=len(pack((self.server.context, self.server.members,
                        tuple((i, tuple(v.items())) for i, v in sorted(self.server.commits.items())), registry,
                        tuple(sorted(self.server.opened)), self.server.frozen, self.server.last_epoch,
                        tuple((i, endpoint(e)) for i, e in sorted(self.server.endpoints.items()))))),
                    client_channel_state_bytes={i: len(pack((client.context, endpoint(client.endpoint))))
                                                for i, client in self.clients.items()},
                    client_nonce_pool_bytes={i: len(pack(tuple((e, c.scalar_bytes(n.secret), n.R, n.salt)
                                                               for e, n in client.pool.items())))
                                             for i, client in self.clients.items()})
