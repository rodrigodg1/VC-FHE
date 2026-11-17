/**
 * Inputs of the SIMPLIFIED ANATEL RQUAL demonstration.
 *
 * The full demonstration in ../anatel-rqual/ reads two committed panels of real
 * measurements and aggregates them inside the trace. This variant does not: its
 * three indicators are supplied directly as declared scalars, so the trace shows
 * how the EXPRESSION composes rather than how a panel is reduced.
 *
 * That is the whole difference, and it is the reason this file has no dataset
 * to cite. Nothing here is measured. Every value is a declared parameter with
 * its own note in anatel-rqual-simplified-params.json, and the seal this variant
 * releases is not an official ANATEL result.
 *
 * Imports nothing beyond node builtins on purpose: the demonstration must be
 * buildable and printable without installing the Node dependency tree.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));

export const SIMPLIFIED_PARAMS_JSON = path.join(scriptDir, "anatel-rqual-simplified-params.json");

function readJson(filePath, label) {
  let raw;
  try {
    raw = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    throw new Error(`${label}: cannot read ${filePath} (${error.message})`);
  }
  try {
    return JSON.parse(raw);
  } catch (error) {
    throw new Error(`${label}: ${filePath} is not valid JSON (${error.message})`);
  }
}

/**
 * Unwraps one declared parameter.
 *
 * The parameter file stores `{value, _note, _source?}` rather than a bare number
 * so that no threshold can travel through the pipeline without the note that
 * says it is a deployment choice and not an ANATEL value.
 */
function param(params, key) {
  const entry = params?.[key];
  if (!entry || typeof entry !== "object" || !("value" in entry)) {
    throw new Error(
      `anatel-rqual-simplified-params.json is missing parameter "${key}" (expected an object with a "value" field)`
    );
  }
  if (typeof entry._note !== "string" || entry._note.length === 0) {
    throw new Error(`anatel-rqual-simplified-params.json parameter "${key}" carries no _note`);
  }
  return entry.value;
}

function assertIntegerArray(values, label, { length } = {}) {
  if (!Array.isArray(values) || values.length === 0) {
    throw new Error(`${label} must be a non-empty array`);
  }
  if (length !== undefined && values.length !== length) {
    throw new Error(`${label} must hold exactly ${length} entries; found ${values.length}`);
  }
  values.forEach((v, i) => {
    if (!Number.isInteger(v) || v < 0) {
      throw new Error(`${label}[${i}] must be a non-negative integer; received ${String(v)}`);
    }
  });
  return values;
}

function assertAscending(values, label) {
  for (let i = 1; i < values.length; i += 1) {
    if (values[i] <= values[i - 1]) {
      throw new Error(`${label} must be strictly ascending; ${values[i - 1]} is followed by ${values[i]}`);
    }
  }
  return values;
}

function assertPermille(value, label) {
  if (!Number.isInteger(value) || value < 0 || value > 1000) {
    throw new Error(`${label} must be an integer in 0..1000 permille; received ${String(value)}`);
  }
  return value;
}

/** Loads the declared deployment parameters, with the disclaimer attached. */
export function loadSimplifiedParams() {
  const raw = readJson(SIMPLIFIED_PARAMS_JSON, "ANATEL RQUAL simplified parameters");
  if (typeof raw._disclaimer !== "string" || raw._disclaimer.length === 0) {
    throw new Error("anatel-rqual-simplified-params.json must carry a top-level _disclaimer");
  }

  const bandEdgesPermille = assertAscending(
    assertIntegerArray(param(raw, "bandEdgesPermille"), "bandEdgesPermille", { length: 3 }),
    "bandEdgesPermille"
  );
  const sealCutoffs = assertAscending(
    assertIntegerArray(param(raw, "sealCutoffs"), "sealCutoffs", { length: 4 }),
    "sealCutoffs"
  );

  const accessBaseBp = param(raw, "accessBaseBp");
  if (!Number.isInteger(accessBaseBp) || accessBaseBp <= 0) {
    throw new Error("accessBaseBp must be a positive integer (it is a public scalar divisor)");
  }
  const complaintsAp = param(raw, "complaintsAp");
  if (!Number.isInteger(complaintsAp) || complaintsAp < 0) {
    throw new Error("complaintsAp must be a non-negative integer");
  }

  // S ranges over 0..3*|bandEdges|. A cut-off at or above the maximum would make
  // the top seal unreachable, which would be a silently dead band rather than an
  // error, so it is rejected here.
  const maxS = 3 * bandEdgesPermille.length;
  for (const [i, cutoff] of sealCutoffs.entries()) {
    if (cutoff >= maxS) {
      throw new Error(
        `sealCutoffs[${i}] = ${cutoff} is not below the maximum composite score ${maxS}; ` +
          "the seal above it could never be reached"
      );
    }
  }

  return {
    disclaimer: raw._disclaimer,
    relationToFullDemo: raw._relationToFullDemo ?? null,
    structureSource: raw._structureSource ?? null,
    expression: raw._expression ?? null,
    iqsPermille: assertPermille(param(raw, "iqsPermille"), "iqsPermille"),
    iqpPermille: assertPermille(param(raw, "iqpPermille"), "iqpPermille"),
    complaintsAp,
    accessBaseBp,
    bandEdgesPermille,
    sealCutoffs,
    sealLabels: param(raw, "sealLabels"),
    notes: Object.fromEntries(
      Object.entries(raw)
        .filter(([key, entry]) => !key.startsWith("_") && entry && typeof entry === "object")
        .map(([key, entry]) => [key, { _note: entry._note, ...(entry._source ? { _source: entry._source } : {}) }])
    )
  };
}

/** The inputs of one run, with the provenance of each one stated explicitly. */
export function simplifiedRqualInputs() {
  const params = loadSimplifiedParams();

  const provenance = {
    disclaimer: params.disclaimer,
    relationToFullDemo: params.relationToFullDemo,
    iqs: {
      indicator: "IQS (Res. 717/2019 Art. 7 VI) - technical measurements",
      role: "encrypted pre-aggregated indicator, permille",
      measured: false,
      source:
        "NOT MEASURED. Supplied directly as a declared scalar. The full demonstration in " +
        "../anatel-rqual/ computes this same number from 16 real drive-test milli-MOS values."
    },
    iqp: {
      indicator: "IQP = ISG (Res. 717/2019 Art. 7 VII) - user survey responses",
      role: "encrypted pre-aggregated indicator, permille",
      measured: false,
      source:
        "NOT MEASURED. Supplied directly as a declared scalar. The full demonstration computes " +
        "this same number from 20 real ACR scores given by 20 distinct human subjects."
    },
    ir: {
      indicator: "IR (Res. 717/2019 Art. 7 V) - user complaints, IR = 1000 * A_P / B_P",
      role:
        "A_P enters the trace as an ENCRYPTED authenticated input; B_P enters as a PUBLIC scalar divisor",
      measured: false,
      source:
        "NOT MEASURED. No complaint register and no access-base filing was consulted; both scalars " +
        "are illustrative period constants, identical to the ones the full demonstration uses."
    },
    everyInputDeclared: true
  };

  return {
    iqsPermille: params.iqsPermille,
    iqpPermille: params.iqpPermille,
    complaintsAp: params.complaintsAp,
    accessBaseBp: params.accessBaseBp,
    params,
    provenance
  };
}
