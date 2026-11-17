/**
 * Restricted expression front end: lexer, parser and AST.
 *
 * This is deliberately NOT a general-purpose expression compiler. It accepts a
 * small, fully specified grammar whose every construct maps onto an operation
 * the protocol can already verify. Anything outside the grammar is rejected
 * with an explicit reason; nothing is approximated and no semantics are
 * silently changed.
 *
 * Grammar (EBNF)
 * --------------
 *   expression := sum
 *   sum        := product ( ("+" | "-") product )*
 *   product    := unary ( ("*" | "/" | "%") unary )*
 *   unary      := "-" unary | primary
 *   primary    := NUMBER
 *                | IDENT
 *                | "(" expression ")"
 *                | CALL "(" expression ("," expression)* ")"
 *   CALL       := "min" | "eq" | "lt" | "gt" | "and" | "or" | "xor"
 *                | "shr" | "cast_u8"
 *   IDENT      := letter (letter | digit | "_")*
 *   NUMBER     := digit+                      (non-negative integers only)
 *
 * Precedence, lowest first: (+ -), (* / %), unary minus, primary.
 * Parentheses override precedence in the usual way.
 */

export class ExpressionError extends Error {
  constructor(message, { code = "E_SYNTAX", position = null, hint = null } = {}) {
    super(message);
    this.name = "ExpressionError";
    this.code = code;
    this.position = position;
    this.hint = hint;
  }
}

/** Binary calls that lower to exactly one micro-instruction. */
export const BINARY_CALLS = Object.freeze({
  min: "MIN", eq: "EQ", lt: "LT", gt: "GT",
  and: "BITAND", or: "BITOR", xor: "BITXOR", shr: "SHR",
});

/** Unary calls that lower to exactly one micro-instruction. */
export const UNARY_CALLS = Object.freeze({ cast_u8: "CAST_U8" });

/** Infix operators and their micro-instruction. */
export const INFIX_OPS = Object.freeze({
  "+": "ADD", "-": "SUB", "*": "MUL", "/": "DIV", "%": "MOD",
});

const IS_DIGIT = (c) => c >= "0" && c <= "9";
const IS_ALPHA = (c) => (c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || c === "_";

export function tokenize(input) {
  const tokens = [];
  let i = 0;
  while (i < input.length) {
    const c = input[i];
    if (c === " " || c === "\t" || c === "\n" || c === "\r") { i++; continue; }
    if (IS_DIGIT(c)) {
      let j = i;
      while (j < input.length && IS_DIGIT(input[j])) j++;
      if (j < input.length && (input[j] === "." || IS_ALPHA(input[j]))) {
        throw new ExpressionError(
          `only non-negative integer literals are supported (near "${input.slice(i, j + 1)}")`,
          { code: "E_UNSUPPORTED_LITERAL", position: i,
            hint: "the micro-ISA operates on unsigned 64-bit integers; rationals and suffixed literals are rejected" });
      }
      tokens.push({ type: "NUMBER", value: input.slice(i, j), pos: i });
      i = j; continue;
    }
    if (IS_ALPHA(c)) {
      let j = i;
      while (j < input.length && (IS_ALPHA(input[j]) || IS_DIGIT(input[j]))) j++;
      tokens.push({ type: "IDENT", value: input.slice(i, j), pos: i });
      i = j; continue;
    }
    if ("+-*/%(),".includes(c)) { tokens.push({ type: c, value: c, pos: i }); i++; continue; }
    if (c === "=") {
      throw new ExpressionError(
        `assignment is not part of an expression (position ${i})`,
        { code: "E_SYNTAX", position: i,
          hint: 'pass only the right-hand side, for example "3*x1 + 2*x2" instead of "y = 3*x1 + 2*x2"' });
    }
    if (c === "^") {
      throw new ExpressionError(
        `exponentiation is not supported (position ${i})`,
        { code: "E_UNSUPPORTED_OP", position: i,
          hint: "write repeated multiplication explicitly, for example x1*x1 instead of x1^2" });
    }
    throw new ExpressionError(`unexpected character "${c}" at position ${i}`, { code: "E_SYNTAX", position: i });
  }
  tokens.push({ type: "EOF", value: "", pos: input.length });
  return tokens;
}

/**
 * Recursive-descent parser producing an AST of the form
 *   {kind:"num", value}  {kind:"var", name}
 *   {kind:"bin", op, left, right}   op in INFIX_OPS
 *   {kind:"call", name, opcode, args}
 *   {kind:"neg", operand}
 */
export function parse(input) {
  if (typeof input !== "string" || input.trim() === "") {
    throw new ExpressionError("expression is empty", { code: "E_EMPTY" });
  }
  const tokens = tokenize(input);
  let p = 0;
  const peek = () => tokens[p];
  const next = () => tokens[p++];
  const expect = (type) => {
    if (peek().type !== type) {
      throw new ExpressionError(
        `expected "${type}" but found "${peek().value || peek().type}" at position ${peek().pos}`,
        { code: "E_SYNTAX", position: peek().pos });
    }
    return next();
  };

  function parseSum() {
    let node = parseProduct();
    while (peek().type === "+" || peek().type === "-") {
      const op = next().type;
      node = { kind: "bin", op, left: node, right: parseProduct() };
    }
    return node;
  }
  function parseProduct() {
    let node = parseUnary();
    while (peek().type === "*" || peek().type === "/" || peek().type === "%") {
      const op = next().type;
      node = { kind: "bin", op, left: node, right: parseUnary() };
    }
    return node;
  }
  function parseUnary() {
    if (peek().type === "-") { next(); return { kind: "neg", operand: parseUnary() }; }
    return parsePrimary();
  }
  function parsePrimary() {
    const t = peek();
    if (t.type === "NUMBER") { next(); return { kind: "num", value: BigInt(t.value), pos: t.pos }; }
    if (t.type === "(") { next(); const e = parseSum(); expect(")"); return e; }
    if (t.type === "IDENT") {
      next();
      const name = t.value;
      if (peek().type === "(") {
        next();
        const args = [parseSum()];
        while (peek().type === ",") { next(); args.push(parseSum()); }
        expect(")");
        const lower = name.toLowerCase();
        if (BINARY_CALLS[lower]) {
          if (args.length !== 2) {
            throw new ExpressionError(`${lower}() takes exactly 2 arguments, received ${args.length}`,
              { code: "E_ARITY", position: t.pos });
          }
          return { kind: "call", name: lower, opcode: BINARY_CALLS[lower], args, pos: t.pos };
        }
        if (UNARY_CALLS[lower]) {
          if (args.length !== 1) {
            throw new ExpressionError(`${lower}() takes exactly 1 argument, received ${args.length}`,
              { code: "E_ARITY", position: t.pos });
          }
          return { kind: "call", name: lower, opcode: UNARY_CALLS[lower], args, pos: t.pos };
        }
        throw new ExpressionError(`unsupported function "${name}()"`, {
          code: "E_UNSUPPORTED_OP", position: t.pos,
          hint: `supported calls: ${[...Object.keys(BINARY_CALLS), ...Object.keys(UNARY_CALLS)].join(", ")}`,
        });
      }
      return { kind: "var", name, pos: t.pos };
    }
    throw new ExpressionError(`unexpected "${t.value || t.type}" at position ${t.pos}`,
      { code: "E_SYNTAX", position: t.pos });
  }

  const ast = parseSum();
  if (peek().type !== "EOF") {
    throw new ExpressionError(
      `unexpected trailing input "${peek().value}" at position ${peek().pos}`,
      { code: "E_SYNTAX", position: peek().pos });
  }
  return ast;
}

/** Ordered list of distinct variable names as they first appear. */
export function collectVariables(ast) {
  const seen = [];
  (function walk(n) {
    if (n.kind === "var") { if (!seen.includes(n.name)) seen.push(n.name); return; }
    if (n.kind === "bin") { walk(n.left); walk(n.right); return; }
    if (n.kind === "neg") { walk(n.operand); return; }
    if (n.kind === "call") { n.args.forEach(walk); }
  })(ast);
  return seen;
}

/** Structural depth, used to enforce the configured complexity limit. */
export function depth(ast) {
  if (ast.kind === "num" || ast.kind === "var") return 1;
  if (ast.kind === "neg") return 1 + depth(ast.operand);
  if (ast.kind === "bin") return 1 + Math.max(depth(ast.left), depth(ast.right));
  return 1 + Math.max(...ast.args.map(depth));
}
