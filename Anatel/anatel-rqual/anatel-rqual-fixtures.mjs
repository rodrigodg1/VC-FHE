/**
 * Inputs for the ANATEL RQUAL regulatory-seal DEMONSTRATION workload.
 *
 * WHAT THIS IS
 * ------------
 * A demonstration-only expression of Brazil's ANATEL RQUAL quality assessment
 * as a non-linear workload, so that a formula written in a government
 * regulation can be shown travelling through the repository's existing dispute
 * pipeline (Besu QBFT, operator, auditors, challenge, bisection, objective leaf
 * resolution, slashing).
 *
 *   technical measurements  -> IQS
 *   user survey responses   -> IQP = ISG
 *   user complaints         -> IR = 1000 * A_P / B_P
 *   S = F(IQS) + F(IQP) + F(IR)   ->   regulatory quality seal
 *
 * WHAT WAS VERIFIED AGAINST THE REGULATION
 * ----------------------------------------
 * Only the STRUCTURE. Resolucao 717/2019 Art. 7 defines IQS (item VI), IQP
 * (item VII) and IR (item V); Art. 11 assigns quality seals A to E. The evaluation
 * does NOT publish the F(.) mapping or any numeric band edge; those live in
 * Anexo I / Resolucao Interna 444/2025, which was NOT consulted. Every weight,
 * threshold and band edge therefore lives in `anatel-rqual-params.json` as a
 * declared deployment parameter with an explicit note. This repository does NOT
 * reproduce ANATEL's official numbers.
 *
 * WHERE THE DATA COMES FROM
 * -------------------------
 * No value here is synthetic. The two measured panels are committed fixtures
 * that already back evaluated workloads:
 *
 *   IQS  <- fhe-pod/scripts/regulatory-fixtures.json, panels.bs1_3000kbps_compliance_16
 *           16 real drive-test milli-MOS values sampled from
 *           VC-FHE/data/MOS_BS_1_Driver_PRB_10.csv. The committed fixture is
 *           reused verbatim; the CSV is not re-derived here.
 *   IQP  <- fhe-pod/scripts/webrtc-fixtures.json, panels.worst_acr_20
 *           20 real ACR scores from 20 distinct human subjects of the
 *           WebRTC-QoE dataset (Zenodo 15836614, CC BY 4.0).
 *   IR   <- the two public scalars of the complaint indicator, declared in
 *           anatel-rqual-params.json with an explicit `_source` saying they are
 *           illustrative period constants and not measured quantities.
 *
 * Imports nothing beyond node builtins on purpose: the demonstration must be
 * buildable and printable without installing the Node dependency tree.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
// The two measurement panels are SHARED with the implementation's evaluated
// workloads and therefore stay in the pod's script directory; only the
// demonstration's own declared parameters live beside this file.
const podScriptsDir = path.resolve(scriptDir, "..", "..", "fhe-pod", "scripts");

export const ANATEL_RQUAL_PARAMS_JSON = path.join(scriptDir, "anatel-rqual-params.json");
export const REGULATORY_FIXTURES_JSON = path.join(podScriptsDir, "regulatory-fixtures.json");
export const WEBRTC_FIXTURES_JSON = path.join(podScriptsDir, "webrtc-fixtures.json");

/** The exact fixture panels this demonstration reads. Named once, here. */
export const IQS_PANEL_NAME = "bs1_3000kbps_compliance_16";
export const IQP_PANEL_NAME = "worst_acr_20";

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
 * The parameter file stores `{value, _note, _source?}` rather than a bare
 * number so that no threshold can travel through the pipeline without the note
 * that says it is a deployment choice and not an ANATEL value.
 */
function param(params, key) {
  const entry = params?.[key];
  if (!entry || typeof entry !== "object" || !("value" in entry)) {
    throw new Error(
      `anatel-rqual-params.json is missing parameter "${key}" (expected an object with a "value" field)`
    );
  }
  if (typeof entry._note !== "string" || entry._note.length === 0) {
    throw new Error(`anatel-rqual-params.json parameter "${key}" carries no _note`);
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

/** Loads the declared deployment parameters, with the disclaimer attached. */
export function loadAnatelRqualParams() {
  const raw = readJson(ANATEL_RQUAL_PARAMS_JSON, "ANATEL RQUAL parameters");
  if (typeof raw._disclaimer !== "string" || raw._disclaimer.length === 0) {
    throw new Error("anatel-rqual-params.json must carry a top-level _disclaimer");
  }

  const bandEdgesPermille = assertAscending(
    assertIntegerArray(param(raw, "bandEdgesPermille"), "bandEdgesPermille", { length: 4 }),
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
  for (const key of ["complaintsAp", "accessBaseBp"]) {
    if (typeof raw[key]._source !== "string" || raw[key]._source.length === 0) {
      throw new Error(`anatel-rqual-params.json parameter "${key}" must declare a _source`);
    }
  }

  return {
    disclaimer: raw._disclaimer,
    structureSource: raw._structureSource ?? null,
    expression: raw._expression ?? null,
    iqsPoorThresholdMilli: param(raw, "iqsPoorThresholdMilli"),
    iqsSessionCount: param(raw, "iqsSessionCount"),
    iqpScaleMax: param(raw, "iqpScaleMax"),
    iqpPanelSize: param(raw, "iqpPanelSize"),
    complaintsAp: param(raw, "complaintsAp"),
    accessBaseBp,
    bandEdgesPermille,
    sealCutoffs,
    sealLabels: param(raw, "sealLabels"),
    notes: Object.fromEntries(
      Object.entries(raw)
        .filter(([key, entry]) => !key.startsWith("_") && entry && typeof entry === "object")
        .map(([key, entry]) => [
          key,
          entry._source ? { _note: entry._note, _source: entry._source } : { _note: entry._note }
        ])
    )
  };
}

/**
 * Builds the demonstration inputs.
 *
 * @returns {{
 *   iqsValuesMilli: number[],
 *   iqpRatings: number[],
 *   complaintsAp: number,
 *   accessBaseBp: number,
 *   params: object,
 *   provenance: object
 * }}
 */
export function anatelRqualInputs() {
  const params = loadAnatelRqualParams();

  const regulatory = readJson(REGULATORY_FIXTURES_JSON, "regulatory fixtures");
  const iqsPanel = regulatory.panels?.[IQS_PANEL_NAME];
  if (!iqsPanel) {
    throw new Error(`regulatory-fixtures.json has no panel "${IQS_PANEL_NAME}"`);
  }
  const iqsValuesMilli = assertIntegerArray(
    iqsPanel.valuesMilli,
    `regulatory panel ${IQS_PANEL_NAME}.valuesMilli`,
    { length: params.iqsSessionCount }
  );

  const webrtc = readJson(WEBRTC_FIXTURES_JSON, "WebRTC-QoE fixtures");
  const iqpPanel = webrtc.panels?.[IQP_PANEL_NAME];
  if (!iqpPanel) {
    throw new Error(`webrtc-fixtures.json has no panel "${IQP_PANEL_NAME}"`);
  }
  const iqpRatings = assertIntegerArray(
    iqpPanel.ratings,
    `WebRTC-QoE panel ${IQP_PANEL_NAME}.ratings`,
    { length: params.iqpPanelSize }
  );
  for (const [i, rating] of iqpRatings.entries()) {
    if (rating < 1 || rating > params.iqpScaleMax) {
      throw new Error(
        `WebRTC-QoE panel ${IQP_PANEL_NAME}.ratings[${i}] = ${rating} is outside the 1..${params.iqpScaleMax} ACR scale`
      );
    }
  }

  const provenance = {
    disclaimer: params.disclaimer,
    iqs: {
      indicator: "IQS (Res. 717/2019 Art. 7 VI) - technical measurements",
      role: "encrypted per-session technical measurements",
      fixtureFile: "fhe-pod/scripts/regulatory-fixtures.json",
      fixturePanel: `panels.${IQS_PANEL_NAME}`,
      datasetId: regulatory.dataset?.id ?? null,
      datasetCitation: regulatory.dataset?.citation ?? null,
      sourceCsv: regulatory.dataset?.sourceCsv ?? null,
      samplingRule: regulatory.dataset?.samplingRule ?? null,
      baseStation: iqsPanel.baseStation ?? null,
      bitrateKbps: iqsPanel.bitrateKbps ?? null,
      mosColumn: iqsPanel.mosColumn ?? null,
      rowNumbers: iqsPanel.rowNumbers ?? null,
      n: iqsValuesMilli.length,
      reuseNote:
        "The committed fixture is reused verbatim; this module does not re-derive values from the CSV."
    },
    iqp: {
      indicator: "IQP = ISG (Res. 717/2019 Art. 7 VII) - user survey responses",
      role: "encrypted per-subject ACR opinion scores",
      fixtureFile: "fhe-pod/scripts/webrtc-fixtures.json",
      fixturePanel: `panels.${IQP_PANEL_NAME}`,
      datasetId: webrtc.dataset?.id ?? null,
      datasetCitation: webrtc.dataset?.citation ?? null,
      sourceCsv: webrtc.dataset?.sourceCsv ?? null,
      scale: webrtc.dataset?.scale ?? null,
      subjects: iqpRatings.length,
      testCondition: iqpPanel.tc === undefined ? null : `TC${iqpPanel.tc}`,
      impairment: iqpPanel.impairment ?? null,
      n: iqpRatings.length,
      subjectNote: "20 distinct human subjects; one ACR score each for the stated test condition."
    },
    ir: {
      indicator: "IR (Res. 717/2019 Art. 7 V) - user complaints, IR = 1000 * A_P / B_P",
      role:
        "A_P enters the trace as the single ENCRYPTED authenticated input of this stage; B_P enters as a PUBLIC scalar divisor",
      complaintsApSource: params.notes.complaintsAp?._source ?? null,
      accessBaseBpSource: params.notes.accessBaseBp?._source ?? null,
      measured: false,
      measurementNote:
        "NOT measured. No complaint register and no access-base filing were consulted; both scalars are illustrative period constants declared in anatel-rqual-params.json."
    },
    parameters: {
      file: "Anatel/anatel-rqual/anatel-rqual-params.json",
      note:
        "Every weight, threshold, band edge and seal cut-off is a declared deployment parameter chosen in the range of such reference values, NOT a value prescribed by ANATEL."
    }
  };

  return {
    iqsValuesMilli,
    iqpRatings,
    complaintsAp: params.complaintsAp,
    accessBaseBp: params.accessBaseBp,
    params,
    provenance
  };
}

export default anatelRqualInputs;
