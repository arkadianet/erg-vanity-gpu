"""SAT search for multiplicative complexity (AND-XOR-NOT circuits).

Model: k AND gates; each AND takes two affine forms of earlier wires;
each output is an affine form of {inputs, AND-outputs}. This is complete
for Boolean maps and allows arbitrary sharing across outputs.

A UNSAT result at k is a lower bound on AND-count in this standard model.
A SAT result is an exact circuit, exhaustively checked on the truth table.
Timeout is 'not found', not a lower bound.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from pysat.solvers import Cadical195


@dataclass
class MCResult:
    k: int
    status: str  # sat / unsat / timeout
    seconds: float
    and_count: int | None = None
    xor_est: int | None = None
    # reconstructed circuit: list of (u_mask, v_mask, u_const, v_const)
    ands: list | None = None
    outs: list | None = None
    out_const: list | None = None


def _timeout_solve(solver: Cadical195, limit_s: float) -> str:
    box: list[str] = ["timeout"]

    def run() -> None:
        box[0] = "sat" if solver.solve() else "unsat"

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(limit_s)
    if t.is_alive():
        try:
            solver.interrupt()
        except Exception:
            pass
        t.join(5)
        return "timeout"
    return box[0]


class _Enc:
    def __init__(self):
        self.n = 0
        self.clauses: list[list[int]] = []

    def var(self) -> int:
        self.n += 1
        return self.n

    def add(self, lits: list[int]) -> None:
        self.clauses.append(lits)

    def AND(self, a: int, b: int) -> int:
        """Tseitin c <=> a ∧ b. a,b may be ±var."""
        c = self.var()
        self.add([-c, a])
        self.add([-c, b])
        self.add([c, -a, -b])
        return c

    def XOR2(self, a: int, b: int) -> int:
        c = self.var()
        # c <=> a ⊕ b
        self.add([-c, a, b])
        self.add([-c, -a, -b])
        self.add([c, -a, b])
        self.add([c, a, -b])
        return c

    def xor_fold(self, lits: list[int]) -> int:
        if not lits:
            v = self.var()
            self.add([-v])  # false
            return v
        acc = lits[0]
        for lit in lits[1:]:
            acc = self.XOR2(acc, lit)
        return acc


def encode_mc(tables: list[list[int]], n_vars: int, k: int) -> tuple[_Enc, dict]:
    """tables[t][x] = output bit t on input x, x in 0..2^n-1."""
    n = n_vars
    nout = len(tables)
    N = 1 << n
    e = _Enc()

    # Coefficients: AND i consumes wires 0..n+i-1 (inputs then previous ANDs)
    # plus a constant.
    u_coeff = []
    v_coeff = []
    u_const = []
    v_const = []
    for i in range(k):
        nw = n + i
        u_coeff.append([e.var() for _ in range(nw)])
        v_coeff.append([e.var() for _ in range(nw)])
        u_const.append(e.var())
        v_const.append(e.var())

    o_coeff = [[e.var() for _ in range(n + k)] for _ in range(nout)]
    o_const = [e.var() for _ in range(nout)]

    # For each input assignment, AND-output values are SAT vars.
    and_val = [[e.var() for _ in range(k)] for _ in range(N)]

    def wire(x: int, j: int) -> int | None:
        """Literal or None for a known constant input bit. AND wires are vars."""
        if j < n:
            return None if False else (("const", (x >> j) & 1))
        return and_val[x][j - n]

    for x in range(N):
        # known input bits
        inbits = [(x >> j) & 1 for j in range(n)]
        for i in range(k):
            # u = u_const ⊕ XOR_j u_coeff[j] ∧ wire[j]
            u_lits = [u_const[i]]
            v_lits = [v_const[i]]
            for j in range(n + i):
                if j < n:
                    if inbits[j]:
                        u_lits.append(u_coeff[i][j])
                        v_lits.append(v_coeff[i][j])
                else:
                    # coeff ∧ and_val
                    u_lits.append(e.AND(u_coeff[i][j], and_val[x][j - n]))
                    v_lits.append(e.AND(v_coeff[i][j], and_val[x][j - n]))
            u = e.xor_fold(u_lits)
            v = e.xor_fold(v_lits)
            prod = e.AND(u, v)
            # and_val[x][i] <=> prod
            av = and_val[x][i]
            e.add([-av, prod])
            e.add([av, -prod])

        for t in range(nout):
            y_lits = [o_const[t]]
            for j in range(n + k):
                if j < n:
                    if inbits[j]:
                        y_lits.append(o_coeff[t][j])
                else:
                    y_lits.append(e.AND(o_coeff[t][j], and_val[x][j - n]))
            y = e.xor_fold(y_lits)
            want = tables[t][x]
            if want:
                e.add([y])
            else:
                e.add([-y])

    meta = {
        "u_coeff": u_coeff,
        "v_coeff": v_coeff,
        "u_const": u_const,
        "v_const": v_const,
        "o_coeff": o_coeff,
        "o_const": o_const,
        "k": k,
        "n": n,
        "nout": nout,
    }
    return e, meta


def solve_mc(tables: list[list[int]], n_vars: int, k: int, timeout_s: float) -> MCResult:
    import time

    t0 = time.time()
    e, meta = encode_mc(tables, n_vars, k)
    solver = Cadical195()
    for cl in e.clauses:
        solver.add_clause(cl)
    status = _timeout_solve(solver, timeout_s)
    dt = time.time() - t0
    res = MCResult(k=k, status=status, seconds=round(dt, 3))
    if status == "sat":
        model = solver.get_model()
        assign = {abs(l): (1 if l > 0 else 0) for l in model}

        def bit(v: int) -> int:
            return assign.get(v, 0)

        ands = []
        for i in range(k):
            um = 0
            vm = 0
            for j, (uc, vc) in enumerate(zip(meta["u_coeff"][i], meta["v_coeff"][i])):
                um |= bit(uc) << j
                vm |= bit(vc) << j
            ands.append((um, vm, bit(meta["u_const"][i]), bit(meta["v_const"][i])))
        outs = []
        oc = []
        for t in range(meta["nout"]):
            m = 0
            for j, c in enumerate(meta["o_coeff"][t]):
                m |= bit(c) << j
            outs.append(m)
            oc.append(bit(meta["o_const"][t]))
        res.and_count = k
        res.ands = ands
        res.outs = outs
        res.out_const = oc
        # XOR estimate: popcount of all linear forms
        xors = 0
        for um, vm, _, _ in ands:
            xors += max(0, um.bit_count() - 1) + max(0, vm.bit_count() - 1)
        for m in outs:
            xors += max(0, m.bit_count() - 1)
        res.xor_est = xors
    solver.delete()
    return res


def eval_mc_circuit(x: int, n: int, ands: list, outs: list, out_const: list) -> int:
    wires = [(x >> i) & 1 for i in range(n)]
    for um, vm, uc, vc in ands:
        u = uc
        v = vc
        for j, w in enumerate(wires):
            if (um >> j) & 1:
                u ^= w
            if (vm >> j) & 1:
                v ^= w
        wires.append(u & v)
    y = 0
    for t, (m, c) in enumerate(zip(outs, out_const)):
        bit = c
        for j, w in enumerate(wires):
            if (m >> j) & 1:
                bit ^= w
        y |= bit << t
    return y


def verify_mc(tables: list[list[int]], n_vars: int, res: MCResult) -> bool:
    if res.status != "sat" or res.ands is None:
        return False
    N = 1 << n_vars
    nout = len(tables)
    for x in range(N):
        y = eval_mc_circuit(x, n_vars, res.ands, res.outs, res.out_const)
        want = 0
        for t in range(nout):
            want |= tables[t][x] << t
        if y != want:
            return False
    return True


def search_mc(
    tables: list[list[int]],
    n_vars: int,
    k_min: int,
    k_max: int,
    timeout_s: float,
) -> list[MCResult]:
    """Scan k = k_min..k_max. Stop after first SAT. Record UNSAT lower bound."""
    out = []
    for k in range(k_min, k_max + 1):
        r = solve_mc(tables, n_vars, k, timeout_s)
        out.append(r)
        if r.status == "sat":
            break
        if r.status == "timeout":
            break
    return out
