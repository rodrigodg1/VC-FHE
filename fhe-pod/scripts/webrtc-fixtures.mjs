/**
 * WebRTC-QoE fixtures for the application-layer evaluation.
 *
 * Dataset: WebRTC-QoE (Univ. of Cagliari), Zenodo 15836614, CC BY 4.0;
 * Bingol et al., Computer Networks 244 (2024) 110356. 20 subjects x 15 test
 * conditions = 300 ACR scores, plus per-frame OpenFace facial features and
 * per-session openSMILE speech features.
 *
 * Sensitivity evidence for the encrypted attributes: gaze reveals identity and
 * personal attributes (Kroeger et al., IFIP AICT 576, 2020,
 * doi:10.1007/978-3-030-42504-3_15); sparse rating histories are
 * re-identifiable (Narayanan and Shmatikov, IEEE S&P 2008,
 * doi:10.1109/SP.2008.33).
 *
 * Regenerate from the raw export:
 *   node scripts/generate-webrtc-fixtures.mjs --require-raw
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
export const WEBRTC_FIXTURES_JSON = path.join(scriptDir, "webrtc-fixtures.json");

const embeddedFixtures = {
  dataset: {
    id: "WebRTC-QoE",
    citation:
      "Bingol et al., Computer Networks 244 (2024) 110356; Zenodo 15836614 (CC BY 4.0)",
    scale: "ACR 1-5 subjective quality ratings",
    subjects: 20,
    conditions: 15,
    scores: 300,
    sourceCsv: "VC-FHE/datasets/raw/webrtc-qoe/Subjective_results_dataset.csv"
  },
  panels: {
    clean_acr_20: {
      tc: 1,
      impairment: { delayMs: 0, jitterMs: 0, lossPercent: 0 },
      n: 20,
      ratings: [5, 4, 3, 5, 3, 3, 5, 5, 3, 3, 3, 4, 4, 4, 3, 5, 3, 5, 4, 4],
      sum: 78,
      mean: 3,
      sumSquares: 318,
      ex2: 15,
      variance: 6
    },
    worst_acr_20: {
      tc: 15,
      impairment: { delayMs: 1000, jitterMs: 500, lossPercent: 30 },
      n: 20,
      ratings: [1, 3, 1, 1, 3, 2, 2, 1, 1, 1, 1, 3, 1, 1, 1, 1, 1, 3, 3, 1],
      sum: 32,
      mean: 1,
      sumSquares: 66,
      ex2: 3,
      variance: 2,
      poorThreshold: 2,
      poorCount: 15
    }
  },
  impairmentAcrGap: {
    op: "SUB",
    cleanSum: 78,
    worstSum: 32,
    gap: 46,
    interpretation:
      "aggregate ACR loss of the 20-subject panel between the unimpaired and the worst test condition"
  },
  gaze: {
    subject: "User1",
    condition: "TC15",
    sourceFile: "facial/User1/TC15_1000-500-30.csv",
    frameCount: 205,
    window: 16,
    stride: 12,
    deviationsMilli: [
      321, 354, 277, 278, 277, 321, 373, 355, 358, 511, 481, 341, 404, 446, 360, 377
    ],
    offCenterThresholdMilli: 350,
    attentionTargetPermille: 500,
    offCenterCount: 10,
    offCenterPermille: 625,
    alarm: 1
  },
  classifier: {
    featureNames: ["gazeDeviationMilli", "blinkAu45Milli", "browAu04Milli"],
    weights: [7361, 8192, 5342],
    bias: -5745145,
    scaleShift: 13,
    fit: "class-balanced linear discriminant over 300 (subject, condition) sessions of per-subject OpenFace features, quantized at 2^13; label poor <=> ACR <= 2",
    accuracyPermille: 517,
    balancedAccuracyPermille: 571,
    sessionCount: 300,
    poorSessions: 105,
    goodSessions: 195,
    featureNote: "Every feature is derived from one subject's own facial and gaze stream for one session; no feature is shared across subjects of a condition.",
    sampleSubject: "User3",
    sampleCondition: "TC15",
    sampleSourceFile: "facial/User3/TC15_1000-500-30.csv",
    sampleFrames: 1127,
    sampleAcr: 1,
    features: [362, 230, 893],
    score: 9319248,
    negativeTotal: 5745145,
    predictedPoor: 1,
    observedPoor: 1,
    observedPoorRatePermille: 750
  }
};

// Keys the per-subject classifier fixture must carry. An export produced by an
// earlier revision (condition-level delay/jitter/loss features) lacks them, and
// silently rendered `undefined` into the published workload limitation. Reject
// it instead, so a stale fixture is a build failure rather than a bad string.
const requiredClassifierKeys = [
  "featureNames", "weights", "bias", "scaleShift", "features",
  "balancedAccuracyPermille", "sessionCount", "sampleSubject",
  "sampleSourceFile", "sampleFrames", "sampleAcr", "observedPoor"
];

function assertClassifierSchema(fixtures, origin) {
  const clf = fixtures?.classifier;
  const missing = requiredClassifierKeys.filter((k) => clf?.[k] === undefined);
  if (missing.length > 0) {
    throw new Error(
      `${origin} carries a classifier fixture without [${missing.join(", ")}]. `
      + "Regenerate it with: node scripts/generate-webrtc-fixtures.mjs --require-raw"
    );
  }
  return fixtures;
}

export function loadWebrtcFixtures() {
  try {
    const parsed = JSON.parse(fs.readFileSync(WEBRTC_FIXTURES_JSON, "utf8"));
    return assertClassifierSchema(parsed, WEBRTC_FIXTURES_JSON);
  } catch (error) {
    if (error instanceof Error && error.message.includes("classifier fixture")) throw error;
    return assertClassifierSchema(embeddedFixtures, "the embedded snapshot");
  }
}

export function webrtcPanel(name) {
  const fixtures = loadWebrtcFixtures();
  const panel = fixtures.panels?.[name];
  if (!panel) {
    throw new Error(`Unknown WebRTC-QoE panel: ${name}`);
  }
  return panel;
}

export function webrtcWorkloadSpecs() {
  const fixtures = loadWebrtcFixtures();
  const worst = fixtures.panels.worst_acr_20;
  const gaze = fixtures.gaze;
  const clf = fixtures.classifier;
  const datasetMeta = {
    dataset: "WebRTC-QoE",
    citation: fixtures.dataset.citation
  };

  const specs = [
    {
      id: "webrtc_worst_acr_variance",
      domain: "QoE / real-time communication",
      title: "WebRTC-QoE opinion dispersion at the worst test condition (20-subject panel)",
      applicability:
        "Session MOS and opinion dispersion over the 20 encrypted ACR scores of one WebRTC test condition, without revealing any subject's score.",
      limitation:
        "Integer floor mean and variance on a 20-subject panel; thresholds are deployment parameters, not dataset ground truth.",
      defaultManipulatedLeafIndex: 83,
      operation: {
        type: "mean_variance",
        values: worst.ratings,
        divisor: worst.n,
        meanThreshold: 2,
        varianceThreshold: 0,
        metadata: {
          ...datasetMeta,
          testCondition: `TC${worst.tc}`,
          impairment: worst.impairment
        }
      }
    },
    {
      id: "webrtc_poor_call_sla",
      domain: "QoE / SLA monitoring",
      title: "WebRTC-QoE poor-call rate against an SLA threshold (20-subject panel)",
      applicability:
        "Counts encrypted ACR scores at or below 'poor' (<=2) across the panel and compares the count against an SLA threshold; only the breach bit is opened.",
      limitation:
        "The poor threshold follows the per-rating condition of the %PoW metric; the SLA threshold is a policy parameter.",
      defaultManipulatedLeafIndex: 51,
      operation: {
        type: "poor_rating_sla",
        values: worst.ratings,
        poorThreshold: worst.poorThreshold,
        slaThreshold: 10,
        metadata: {
          ...datasetMeta,
          testCondition: `TC${worst.tc}`,
          impairment: worst.impairment
        }
      }
    },
    {
      id: "webrtc_poor_call_classifier",
      domain: "ML inference / QoE classification",
      title: "WebRTC-QoE poor-call classifier over encrypted session features",
      applicability:
        "Deterministic encrypted inference of a quantized linear classifier fitted off-chain on human ACR labels over per-subject facial and gaze features; the model weights are public and only the session feature vector, which is biometric-grade user data, is encrypted.",
      limitation: `Accuracy ${clf.accuracyPermille} permille (balanced ${clf.balancedAccuracyPermille}) over ${clf.sessionCount} (subject, condition) sessions; the model is fitted off-chain and the trace verifies one deterministic inference, with no encrypted training. The protocol checks that this fitted model was the one evaluated, not that its prediction matches the subject's rating. A challenge discloses the session's feature vector on-chain.`,
      defaultManipulatedLeafIndex: 6,
      operation: {
        type: "linear_classifier_nd",
        features: clf.features,
        weights: clf.weights,
        bias: clf.bias,
        scaleShift: clf.scaleShift,
        expectedClass: clf.predictedPoor,
        metadata: {
          ...datasetMeta,
          testCondition: clf.sampleCondition,
          subject: clf.sampleSubject,
          sourceFile: clf.sampleSourceFile,
          frames: clf.sampleFrames,
          observedAcr: clf.sampleAcr,
          featureNames: clf.featureNames,
          fit: clf.fit,
          accuracyPermille: clf.accuracyPermille,
          balancedAccuracyPermille: clf.balancedAccuracyPermille,
          sessionCount: clf.sessionCount,
          observedPoor: clf.observedPoor,
          observedAcr: clf.sampleAcr,
          featureNote: clf.featureNote
        }
      }
    }
  ];

  if (gaze) {
    specs.push({
      id: "webrtc_gaze_attention_monitor",
      domain: "QoE / biometric-grade input",
      title: "WebRTC-QoE gaze attention monitor over an encrypted per-frame stream",
      applicability:
        "Per-frame gaze deviation magnitudes enter the trace encrypted, are compared against a public deviation threshold, counted homomorphically, and reduced to one attention alarm bit; no frame value is part of the released output.",
      limitation: `Window of ${gaze.window} frames sampled at stride ${gaze.stride} from the ${gaze.frameCount} successful frames of one session; a full-session trace is not measured because challenged disclosure is linear in the leaf count. A challenge still discloses the window's deviation values on-chain.`,
      defaultManipulatedLeafIndex: 33,
      operation: {
        type: "gaze_attention_monitor",
        deviationsMilli: gaze.deviationsMilli,
        offCenterThresholdMilli: gaze.offCenterThresholdMilli,
        attentionTargetPermille: gaze.attentionTargetPermille,
        metadata: {
          ...datasetMeta,
          subject: gaze.subject,
          testCondition: gaze.condition,
          sourceFile: gaze.sourceFile,
          encoding:
            "owner-side |gaze_angle_x| + |gaze_angle_y| in milliradians; the trace never receives a signed gaze vector"
        }
      }
    });
  }

  return specs;
}
