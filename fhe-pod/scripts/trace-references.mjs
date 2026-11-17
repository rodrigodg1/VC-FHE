// Validate structural references without using private values to choose wires.
export function explicitTraceReferences(leaves) {
  if (!leaves.some(leaf => leaf.lhsRef || leaf.rhsRef)) return null;
  const inputs = new Set();
  const refs = leaves.map((leaf, i) => {
    const check = (ref, side) => {
      if (ref?.kind === "constant" && /^\d+$/.test(ref.value) && BigInt(ref.value) < 1n << 64n) {
        if (BigInt(ref.value) !== BigInt(leaf[side])) throw new Error(`constant mismatch at leaf ${i}`);
        return ref;
      }
      if (!Number.isSafeInteger(ref?.index) || ref.index < 0) throw new Error(`missing source at leaf ${i}`);
      if (ref.kind === "input") { inputs.add(ref.index); return ref; }
      if (ref.kind === "output" && ref.index < i) return ref;
      throw new Error(`forward, cyclic or unknown source at leaf ${i}`);
    };
    return { lhs: check(leaf.lhsRef, "lhs"), rhs: check(leaf.rhsRef, "rhs") };
  });
  const indices = [...inputs].sort((a, b) => a - b);
  if (indices.some((index, i) => index !== i)) throw new Error("input indices must be dense");
  return refs;
}
