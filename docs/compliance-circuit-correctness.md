# Correctness of the evaluated compliance circuits

This note specifies the all-sessions and selected-area quality tests and explains
why the explicit circuits compute them under the conditions below. It concerns
application-circuit correctness. Soundness of trace acceptance and authorized
plaintext recovery additionally depend on the protocol's binding, audit,
adjudication and release assumptions.

## Inputs and predicates

Let $n$ be the total number of records and $G$ the number whose encoded quality
scores strictly exceed the public quality threshold. Let $n_c$ be the number of
records in the selected geographic cell and $G_c$ the number of those records
whose scores exceed the threshold. The required proportion is $\theta/1000$.

The all-sessions circuit computes

$$
[1000G \geq \theta n].
$$

The selected-area circuit computes

$$
[n_c > 0] \land [1000G_c \geq \theta n_c].
$$

Here $[P]$ is 1 when predicate $P$ holds and 0 otherwise. The outputs remain
encrypted until authorized release. An empty regional selection returns zero.

In the evaluation, the encoded score threshold is 2000 and $\theta=950$, which
represents 95%. Scores equal to 2000 do not count as qualifying records.

## Correctness conditions

The argument assumes:

- Valid, well-formed encrypted unsigned inputs within their declared ranges,
  with public parameters satisfying the circuit's admission rules.
- Correct FHE evaluation of all operations in the task.
- An integer record count $n\geq2$ and integer target $1\leq\theta\leq1000$.
- The arithmetic bound $1000n<2^{64}$.

The record count is the total input count, not the regional count. Thus
$n\geq2$ does not require $n_c\geq2$ and does not exclude an empty region.
These arithmetic conditions do not override deployment trace limits or establish
support for arbitrary input sizes.

## Correctness argument

1. Each quality comparison produces a bit indicating whether its record exceeds
   the threshold. For regional tasks, a cell-equality bit identifies membership.
   Their conjunction selects exactly the qualifying regional records.
2. Induction over the addition trees gives $G$, $n_c$ and $G_c$ as appropriate.
   Every partial count is at most $n$. Padding a sum tree with zeros preserves
   its total.
3. Since every count is at most $n$ and $\theta\leq1000$, both sides of each
   scaled comparison are at most $1000n<2^{64}$. Counts and scaled products
   therefore fit the unsigned 64-bit domain without overflow.
4. The global comparison gives the first predicate. The regional comparison
   conjoined with $[n_c>0]$ gives the second, avoiding a positive result for an
   empty selection.
5. Padding the instruction trace with additions of zero to the previous terminal
   result preserves the output. Operand references are fixed from public
   dimensions and parameters before private input values are supplied.

Under FHE correctness, these operations preserve the stated plaintext predicates
while operating on ciphertexts. This argument does not prove that an operator
executed the circuit correctly. Soundness of canonical trace acceptance requires
the protocol assumptions, including timely honest audit coverage, data
availability, deterministic recomputation and a sound adjudicator quorum.
Public admission checks do not prove that owners encrypted truthful measurements
or values within their declared ranges.

## Source and checks

The [circuit compiler](../fhe-pod/scripts/compliance-circuit.mjs) fixes explicit
input, previous-output and constant references. The
[instruction semantics](../fhe-pod/scripts/micro-isa.mjs) define the supported
operations. Existing [reference-circuit tests](../fhe-pod/scripts/compliance-circuit.test.mjs)
cover qualifying and failing cases, equal-valued records, empty regional
selections, padding and malformed references.

Run from the repository root:

```bash
node --test fhe-pod/scripts/compliance-circuit.test.mjs
```

These are functional reference-circuit checks. They do not establish FHE
confidentiality, a negligible task-level decryption-error probability or the
soundness of optimistic trace acceptance.

