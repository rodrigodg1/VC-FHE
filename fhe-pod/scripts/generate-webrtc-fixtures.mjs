/**
 * Regenerate the WebRTC-QoE fixtures used by the application-layer evaluation.
 *
 * Dataset: WebRTC-QoE (Univ. of Cagliari), Zenodo record 15836614, CC BY 4.0.
 *   Bingol et al., Computer Networks 244 (2024) 110356 (dataset experiment);
 *   Bingol et al., ACM TOMM 2024, doi:10.1145/3638251 (QoE estimation from
 *   facial and speech features on this data).
 *   20 subjects x 15 test conditions (TCs) = 300 ACR scores; OpenFace
 *   per-frame facial features; openSMILE per-session speech features.
 *
 * Raw inputs expected under VC-FHE/datasets/raw/webrtc-qoe:
 *   Subjective_results_dataset.csv
 *   facial/User<k>/TC<n>_<delay>-<jitter>-<loss>.csv   (OpenFace output)
 *
 * Selection rules are fixed here and recorded in the generated fixture so the
 * panels are reproducible without redistributing the raw export:
 *   - clean condition   = the TC with delay 0, jitter 0, packet loss 0;
 *   - worst condition   = the TC with the highest delay, jitter and loss;
 *   - gaze session      = User1 at the worst condition, deterministic stride
 *                         sample of GAZE_WINDOW successful frames;
 *   - classifier sample = the worst condition's impairment triple.
 *
 * Usage (from VC-FHE/fhe-pod):
 *   node scripts/generate-webrtc-fixtures.mjs [--raw <dir>] [--require-raw]
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "..", "..");
const OUT_JSON = path.join(scriptDir, "webrtc-fixtures.json");

const GAZE_WINDOW = 16;
const GAZE_SUBJECT = "User1";

function argValue(name, fallback) {
  const idx = process.argv.indexOf(`--${name}`);
  return idx >= 0 && process.argv[idx + 1] ? process.argv[idx + 1] : fallback;
}

const rawDir = path.resolve(
  argValue("raw", path.join(repoRoot, "datasets", "raw", "webrtc-qoe"))
);
const requireRaw = process.argv.includes("--require-raw");

function readCsv(file) {
  const text = fs.readFileSync(file, "utf8").replace(/\r\n/g, "\n").trim();
  const [headerLine, ...lines] = text.split("\n");
  const header = headerLine.split(",").map((h) => h.trim());
  return lines.map((line) => {
    const cells = line.split(",").map((c) => c.trim());
    return Object.fromEntries(header.map((h, i) => [h, cells[i]]));
  });
}

/** Integer mean/variance exactly as lowerMeanVariance computes them. */
function integerStats(values, divisor) {
  const sum = values.reduce((a, b) => a + b, 0);
  const mean = Math.floor(sum / divisor);
  const ss = values.reduce((a, b) => a + b * b, 0);
  const ex2 = Math.floor(ss / divisor);
  return { sum, mean, sumSquares: ss, ex2, variance: ex2 - mean * mean };
}

const subjectivePath = path.join(rawDir, "Subjective_results_dataset.csv");
if (!fs.existsSync(subjectivePath)) {
  const message = `WebRTC-QoE subjective CSV not found at ${subjectivePath}. Run: node datasets/download/download-webrtc-qoe.mjs --yes`;
  if (requireRaw) {
    console.error(message);
    process.exit(1);
  }
  console.warn(`${message}\nKeeping the committed ${path.basename(OUT_JSON)}.`);
  process.exit(0);
}

const rows = readCsv(subjectivePath);
const subjects = Object.keys(rows[0])
  .filter((k) => /^User\d+$/.test(k))
  .sort((a, b) => Number(a.slice(4)) - Number(b.slice(4)));

const conditions = rows.map((r) => ({
  tc: Number(r["Test Condition (TC)"]),
  delayMs: Number(r["Delay [ms]"]),
  jitterMs: Number(r["Jitter [ms]"]),
  lossPercent: Number(r["Packet Loss Rate [%]"]),
  ratings: subjects.map((s) => Number(r[s]))
}));

const clean = conditions.find(
  (c) => c.delayMs === 0 && c.jitterMs === 0 && c.lossPercent === 0
);
const worst = conditions.reduce((acc, c) =>
  c.delayMs + c.jitterMs + c.lossPercent * 100 >
  acc.delayMs + acc.jitterMs + acc.lossPercent * 100
    ? c
    : acc
);
if (!clean) {
  console.error("no unimpaired test condition (0/0/0) found");
  process.exit(1);
}

const cleanStats = integerStats(clean.ratings, clean.ratings.length);
const worstStats = integerStats(worst.ratings, worst.ratings.length);
const POOR_THRESHOLD = 2;
const worstPoorCount = worst.ratings.filter((v) => v <= POOR_THRESHOLD).length;

/* ---------------------------------------------------------------------- */
/* Gaze window: per-frame deviation magnitude in milliradians.             */
/* The owner encodes |gaze_angle_x| + |gaze_angle_y| locally; the trace    */
/* never receives a raw signed gaze vector.                               */
/* ---------------------------------------------------------------------- */
function gazeWindow() {
  const dir = path.join(rawDir, "facial", GAZE_SUBJECT);
  if (!fs.existsSync(dir)) return null;
  const suffix = `TC${worst.tc}_${worst.delayMs}-${worst.jitterMs}-${worst.lossPercent}.csv`;
  const file = path.join(dir, suffix);
  if (!fs.existsSync(file)) return null;

  const frames = readCsv(file).filter((r) => Number(r.success) === 1);
  if (frames.length < GAZE_WINDOW) return null;
  const stride = Math.floor(frames.length / GAZE_WINDOW);
  const sampled = Array.from({ length: GAZE_WINDOW }, (_, i) => frames[i * stride]);
  const deviationsMilli = sampled.map((r) =>
    Math.round(
      (Math.abs(Number(r.gaze_angle_x)) + Math.abs(Number(r.gaze_angle_y))) * 1000
    )
  );
  return {
    subject: GAZE_SUBJECT,
    condition: `TC${worst.tc}`,
    sourceFile: `facial/${GAZE_SUBJECT}/${suffix}`,
    frameCount: frames.length,
    window: GAZE_WINDOW,
    stride,
    deviationsMilli
  };
}

const gaze = gazeWindow();
if (!gaze && requireRaw) {
  console.error("OpenFace gaze file for the worst condition not found");
  process.exit(1);
}

const OFF_CENTER_THRESHOLD_MILLI = 350;
const ATTENTION_TARGET_PERMILLE = 500;
const gazeOffCount = gaze
  ? gaze.deviationsMilli.filter((d) => d > OFF_CENTER_THRESHOLD_MILLI).length
  : null;

/* ---------------------------------------------------------------------- */
/* Poor-call classifier over PER-SUBJECT biometric features.               */
/*                                                                          */
/* An earlier revision classified from the test condition's delay, jitter   */
/* and loss. Those three numbers are identical for all 20 subjects of a     */
/* condition, so they are not user data and no classifier built on them can */
/* separate subjects: its accuracy was capped at 777 permille by            */
/* construction. This version derives one feature vector per (subject,      */
/* condition) session from that subject's own OpenFace output, so every     */
/* encrypted operand is biometric-grade user data, matching the per-subject */
/* estimation task of the dataset's companion work (DOI 10.1145/3638251).   */
/*                                                                          */
/* Features (all non-negative integers in milli-units, one per session):    */
/*   f0 gaze deviation   mean(|gaze_angle_x| + |gaze_angle_y|)              */
/*   f1 blink intensity  mean(AU45_r)                                       */
/*   f2 brow lowerer     mean(AU04_r)                                       */
/*   f3 head motion      mean(|pose_Rx| + |pose_Ry|)                        */
/* A feature whose column is absent from the export is dropped, and the fit */
/* proceeds on the remaining ones; the emitted fixture records which were   */
/* used. The weights are fitted off-chain here and are public; only the     */
/* session feature vector is encrypted.                                     */
/* ---------------------------------------------------------------------- */
const FEATURE_SPECS = [
  {
    name: "gazeDeviationMilli",
    columns: ["gaze_angle_x", "gaze_angle_y"],
    value: (r) =>
      Math.abs(Number(r.gaze_angle_x)) + Math.abs(Number(r.gaze_angle_y))
  },
  { name: "blinkAu45Milli", columns: ["AU45_r"], value: (r) => Number(r.AU45_r) },
  { name: "browAu04Milli", columns: ["AU04_r"], value: (r) => Number(r.AU04_r) },
  {
    name: "headMotionMilli",
    columns: ["pose_Rx", "pose_Ry"],
    value: (r) => Math.abs(Number(r.pose_Rx)) + Math.abs(Number(r.pose_Ry))
  }
];

function conditionSuffix(c) {
  return `TC${c.tc}_${c.delayMs}-${c.jitterMs}-${c.lossPercent}.csv`;
}

/** One integer feature vector per (subject, condition) session, plus its ACR label. */
function perSubjectSessions() {
  const facialRoot = path.join(rawDir, "facial");
  if (!fs.existsSync(facialRoot)) return null;
  let active = null;
  const sessions = [];
  for (const [subjectIndex, subject] of subjects.entries()) {
    for (const c of conditions) {
      const file = path.join(facialRoot, subject, conditionSuffix(c));
      if (!fs.existsSync(file)) continue;
      const frames = readCsv(file).filter((r) => Number(r.success) === 1);
      if (frames.length === 0) continue;
      if (active === null) {
        const header = Object.keys(frames[0]);
        active = FEATURE_SPECS.filter((f) => f.columns.every((col) => header.includes(col)));
        if (active.length === 0) return null;
      }
      const features = active.map((f) => {
        const total = frames.reduce((acc, r) => {
          const v = f.value(r);
          return acc + (Number.isFinite(v) ? v : 0);
        }, 0);
        return Math.max(0, Math.round((total / frames.length) * 1000));
      });
      sessions.push({
        subject,
        subjectIndex,
        tc: c.tc,
        conditionFile: `facial/${subject}/${conditionSuffix(c)}`,
        frames: frames.length,
        features,
        acr: c.ratings[subjectIndex],
        poor: c.ratings[subjectIndex] <= POOR_THRESHOLD ? 1 : 0
      });
    }
  }
  if (sessions.length === 0 || active === null) return null;
  return { sessions, featureNames: active.map((f) => f.name) };
}

/**
 * Class-balanced linear discriminant, quantized to integers.
 *
 * The direction is the difference of the per-class feature means, scaled so
 * the largest weight magnitude reaches 2^scaleShift; the bias is then chosen
 * by scanning the observed score range for the balanced-accuracy maximum.
 * Deterministic: no randomness, no iteration order dependence.
 */
function fitPoorCallClassifier(sessions, scaleShift) {
  const dim = sessions[0].features.length;
  const poor = sessions.filter((s) => s.poor === 1);
  const good = sessions.filter((s) => s.poor === 0);
  if (poor.length === 0 || good.length === 0) return null;
  const meanOf = (set, i) => set.reduce((a, s) => a + s.features[i], 0) / set.length;
  const raw = Array.from({ length: dim }, (_, i) => meanOf(poor, i) - meanOf(good, i));
  const maxAbs = Math.max(...raw.map(Math.abs));
  if (maxAbs === 0) return null;
  const weights = raw.map((w) => Math.round((w / maxAbs) * (1 << scaleShift)));
  const rawScore = (s) => s.features.reduce((acc, x, i) => acc + x * weights[i], 0);
  const scores = sessions.map(rawScore).sort((a, b) => a - b);
  let best = null;
  for (let k = 0; k <= scores.length; k += 1) {
    // Candidate cut between two observed scores; bias = -cut so that
    // (score + bias) >> scaleShift > 0 marks the poor side.
    const lo = k === 0 ? scores[0] - 1 : scores[k - 1];
    const hi = k === scores.length ? scores[scores.length - 1] + 1 : scores[k];
    const cut = Math.floor((lo + hi) / 2);
    let tp = 0, tn = 0;
    for (const s of sessions) {
      const predicted = (rawScore(s) - cut) >> scaleShift > 0 ? 1 : 0;
      if (predicted === 1 && s.poor === 1) tp += 1;
      if (predicted === 0 && s.poor === 0) tn += 1;
    }
    const balanced = tp / poor.length + tn / good.length;
    if (best === null || balanced > best.balanced) {
      best = { balanced, bias: -cut, correct: tp + tn };
    }
  }
  return {
    weights,
    bias: best.bias,
    scaleShift,
    accuracyPermille: Math.round((best.correct / sessions.length) * 1000),
    balancedAccuracyPermille: Math.round((best.balanced / 2) * 1000),
    poorSessions: poor.length,
    goodSessions: good.length
  };
}

const CLASSIFIER_SCALE_SHIFT = 13;
const perSubject = perSubjectSessions();
if (!perSubject) {
  const message =
    `Per-subject OpenFace features not found under ${path.join(rawDir, "facial")}. ` +
    `The poor-call classifier is fitted on per-subject biometric features and cannot be ` +
    `rebuilt without them. Run: node datasets/download/download-webrtc-qoe.mjs --yes`;
  if (requireRaw) {
    console.error(message);
    process.exit(1);
  }
  console.warn(`${message}\nKeeping the committed ${path.basename(OUT_JSON)}.`);
  process.exit(0);
}
const fit = fitPoorCallClassifier(perSubject.sessions, CLASSIFIER_SCALE_SHIFT);
if (!fit) {
  const message = "per-subject features carry no usable class separation";
  if (requireRaw) {
    console.error(message);
    process.exit(1);
  }
  console.warn(`${message}\nKeeping the committed ${path.basename(OUT_JSON)}.`);
  process.exit(0);
}

// Evaluate one real session: prefer a correctly classified poor session of the
// worst condition, so the honest trace is a correct inference on real data.
const scoreOf = (s) =>
  s.features.reduce((acc, x, i) => acc + x * fit.weights[i], 0) + fit.bias;
const predictedOf = (s) => (scoreOf(s) >> fit.scaleShift > 0 ? 1 : 0);
const sample =
  perSubject.sessions.find(
    (s) => s.tc === worst.tc && s.poor === 1 && predictedOf(s) === 1
  ) ??
  perSubject.sessions.find((s) => predictedOf(s) === s.poor) ??
  perSubject.sessions[0];

const CLASSIFIER = {
  featureNames: perSubject.featureNames,
  weights: fit.weights,
  bias: fit.bias,
  scaleShift: fit.scaleShift,
  fit:
    `class-balanced linear discriminant over ${perSubject.sessions.length} (subject, condition) ` +
    `sessions of per-subject OpenFace features, quantized at 2^${fit.scaleShift}; ` +
    `label poor <=> ACR <= ${POOR_THRESHOLD}`,
  accuracyPermille: fit.accuracyPermille,
  balancedAccuracyPermille: fit.balancedAccuracyPermille,
  sessionCount: perSubject.sessions.length,
  poorSessions: fit.poorSessions,
  goodSessions: fit.goodSessions,
  featureNote:
    "Every feature is derived from one subject's own facial and gaze stream for one session; no feature is shared across subjects of a condition."
};

const classifierFeatures = sample.features;
const classifierScore = classifierFeatures.reduce(
  (acc, x, i) => acc + x * CLASSIFIER.weights[i],
  0
);

const fixtures = {
  dataset: {
    id: "WebRTC-QoE",
    citation:
      "Bingol et al., Computer Networks 244 (2024) 110356; Zenodo 15836614 (CC BY 4.0)",
    scale: "ACR 1-5 subjective quality ratings",
    subjects: subjects.length,
    conditions: conditions.length,
    scores: subjects.length * conditions.length,
    sourceCsv: "VC-FHE/datasets/raw/webrtc-qoe/Subjective_results_dataset.csv"
  },
  panels: {
    clean_acr_20: {
      tc: clean.tc,
      impairment: {
        delayMs: clean.delayMs,
        jitterMs: clean.jitterMs,
        lossPercent: clean.lossPercent
      },
      n: clean.ratings.length,
      ratings: clean.ratings,
      ...cleanStats,
      subjects
    },
    worst_acr_20: {
      tc: worst.tc,
      impairment: {
        delayMs: worst.delayMs,
        jitterMs: worst.jitterMs,
        lossPercent: worst.lossPercent
      },
      n: worst.ratings.length,
      ratings: worst.ratings,
      ...worstStats,
      poorThreshold: POOR_THRESHOLD,
      poorCount: worstPoorCount,
      subjects
    }
  },
  impairmentAcrGap: {
    op: "SUB",
    cleanSum: cleanStats.sum,
    worstSum: worstStats.sum,
    gap: cleanStats.sum - worstStats.sum,
    interpretation:
      "aggregate ACR loss of the 20-subject panel between the unimpaired and the worst test condition"
  },
  gaze: gaze
    ? {
        ...gaze,
        offCenterThresholdMilli: OFF_CENTER_THRESHOLD_MILLI,
        attentionTargetPermille: ATTENTION_TARGET_PERMILLE,
        offCenterCount: gazeOffCount,
        offCenterPermille: Math.floor((gazeOffCount * 1000) / GAZE_WINDOW),
        alarm:
          gazeOffCount * 1000 > GAZE_WINDOW * ATTENTION_TARGET_PERMILLE ? 1 : 0
      }
    : null,
  classifier: {
    ...CLASSIFIER,
    sampleSubject: sample.subject,
    sampleCondition: `TC${sample.tc}`,
    sampleSourceFile: sample.conditionFile,
    sampleFrames: sample.frames,
    sampleAcr: sample.acr,
    features: classifierFeatures,
    score: classifierScore,
    negativeTotal: -CLASSIFIER.bias,
    predictedPoor: predictedOf(sample),
    observedPoor: sample.poor,
    observedPoorRatePermille: Math.floor((worstPoorCount * 1000) / worst.ratings.length)
  }
};

fs.writeFileSync(OUT_JSON, `${JSON.stringify(fixtures, null, 2)}\n`);
console.log(`wrote ${OUT_JSON}`);
console.log(
  `clean TC${clean.tc} sum=${cleanStats.sum}  worst TC${worst.tc} sum=${worstStats.sum}  gap=${fixtures.impairmentAcrGap.gap}`
);
console.log(
  `worst panel: mean=${worstStats.mean} variance=${worstStats.variance} poorCount=${worstPoorCount}/${worst.ratings.length}`
);
if (gaze) {
  console.log(
    `gaze window: ${gaze.window} frames (stride ${gaze.stride} of ${gaze.frameCount}) offCenter=${gazeOffCount} alarm=${fixtures.gaze.alarm}`
  );
}
console.log(
  `classifier: ${CLASSIFIER.featureNames.length} per-subject features, ` +
    `fit on ${CLASSIFIER.sessionCount} sessions (${CLASSIFIER.poorSessions} poor), ` +
    `accuracy ${CLASSIFIER.accuracyPermille} permille (balanced ${CLASSIFIER.balancedAccuracyPermille})`
);
console.log(
  `  sample ${sample.subject}/TC${sample.tc}: features=[${classifierFeatures.join(", ")}] ` +
    `predictedPoor=${predictedOf(sample)} observedPoor=${sample.poor} (ACR ${sample.acr})`
);
