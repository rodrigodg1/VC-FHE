/**
 * Derive the LINEAR QoE example cases from the repository's REAL datasets.
 *
 * Sources (no synthetic values anywhere):
 *   1. STAV360 subjective ratings (ACR 1..5). NOT redistributed here (no
 *      upstream license); obtained on demand from the authors' mirror
 *      https://github.com/SLG-European-Projects/STAV360 via
 *      VC-FHE/datasets/download/download-stav360.mjs. Record: IEEE DataPort
 *      doi:10.21227/BCPT-3904; experiment: Mahmoud et al., ICIT 2025,
 *      doi:10.1109/ICIT64950.2025.11049277.
 *   2. Drive-test video MOS        -> VC-FHE/data/MOS_BS_1_Driver_PRB_10.csv
 *      (per-row MOS at 3000 kbps, milli-MOS scale; 5G-QoERA corpus, GPL-3.0,
 *      Boffetti et al., IEEE WCNC 2025)
 *
 * Case 1 (SUM, mean): the first PANEL_N ratings, ordered by user id, of one
 * fixed STAV360 (video, tiling pattern) session. The verified statistic is the
 * encrypted SUM; the session MOS mean is sum / N after decryption, N public.
 *
 * Case 2 (SUM, compliance): the same deterministic 16-row stride sample used
 * by the evaluation's regulatory fixture (row[i*floor(validRows/16)], i in
 * 0..15) over MOS_3000kbps; each owner contributes the 0/1 indicator
 * "session is good" (mosMilli > 2000). The verified SUM is the good-session
 * count; the regulator compares count*1000 against n*targetPermille (950).
 *
 * The output feeds the real-TFHE Rust emitter:
 *   cargo run --release --bin output_binding_tfhe -- \
 *     emit-onchain-mk-cases <out.json> linear-cases.qoe.json
 *
 * Run: node generate-linear-cases.mjs
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const vcfheRoot = path.join(here, "..", "..", "..", "..");
// The ratings export is looked up in the datasets/ download location first,
// then in the legacy in-place location kept for local runs of the Rust
// emitter (run-experiment.sh fetches it there on demand).
const STAV360_CANDIDATES = [
  path.join(vcfheRoot, "datasets", "raw", "stav360", "Raw_Ratings.csv"),
  path.join(vcfheRoot, "BN254-Signatures", "Users_Ratings.csv"),
];
const STAV360_CSV = STAV360_CANDIDATES.find((p) => fs.existsSync(p));
if (!STAV360_CSV) {
  console.error("STAV360 ratings not found. Run: node VC-FHE/datasets/download/download-stav360.mjs");
  console.error(`Searched: ${STAV360_CANDIDATES.join(" ; ")}`);
  process.exit(1);
}
const DRIVETEST_CSV = path.join(vcfheRoot, "data", "MOS_BS_1_Driver_PRB_10.csv");
const WEBRTC_CSV = path.join(
  vcfheRoot, "datasets", "raw", "webrtc-qoe", "Subjective_results_dataset.csv"
);

// Fixed, documented selections (same objects used by the evaluation fixtures).
const PANEL_VIDEO = "FeedTheDucks";
const PANEL_PATTERN = "Pattern2_Uniform_Mid";
const PANEL_N = 16;
const MOS_COLUMN = "MOS_3000kbps";
const POOR_THRESHOLD_MILLI = 2000;
const TARGET_PERMILLE = 950;
const STRIDE_PANEL_N = 16;

function parseCsvLine(line) {
  return line.split(",");
}

// ---- Case 1: STAV360 session panel (ratings 1..5) -------------------------
function stav360Panel() {
  const raw = fs.readFileSync(STAV360_CSV, "utf8").trim().split(/\r?\n/);
  const header = parseCsvLine(raw[0]);
  const col = (name) => {
    const i = header.indexOf(name);
    if (i < 0) throw new Error(`column ${name} missing in Users_Ratings.csv`);
    return i;
  };
  const [cUser, cVideo, cPattern, cRating] = [
    col("user"), col("video_title"), col("video_tiling_pattern"), col("rating"),
  ];
  const rows = raw.slice(1).map(parseCsvLine)
    .filter((r) => r[cVideo] === PANEL_VIDEO && r[cPattern] === PANEL_PATTERN)
    .map((r) => ({ user: r[cUser], rating: Number(r[cRating]) }))
    .sort((a, b) => a.user.localeCompare(b.user));
  if (rows.length < PANEL_N) {
    throw new Error(`only ${rows.length} ratings for ${PANEL_VIDEO}/${PANEL_PATTERN}; need ${PANEL_N}`);
  }
  const selected = rows.slice(0, PANEL_N);
  const values = selected.map((r) => {
    if (!Number.isInteger(r.rating) || r.rating < 1 || r.rating > 5) {
      throw new Error(`non-ACR rating ${r.rating} for user ${r.user}`);
    }
    return r.rating;
  });
  return { values, users: selected.map((r) => r.user) };
}

// ---- Case 2: drive-test compliance indicators -----------------------------
function driveTestIndicators() {
  const raw = fs.readFileSync(DRIVETEST_CSV, "utf8").trim().split(/\r?\n/);
  const header = parseCsvLine(raw[0]);
  const mosIdx = header.indexOf(MOS_COLUMN);
  if (mosIdx < 0) throw new Error(`column ${MOS_COLUMN} missing in drive-test CSV`);
  const validRows = raw.length - 1;
  const stride = Math.floor(validRows / STRIDE_PANEL_N);
  const rowNumbers = [];
  const valuesMilli = [];
  for (let i = 0; i < STRIDE_PANEL_N; i++) {
    const rowNumber = 1 + i * stride; // 1-based data row, matching the evaluation fixture rule
    const cells = parseCsvLine(raw[rowNumber]);
    const mosMilli = Math.round(Number(cells[mosIdx]) * 1000);
    if (!Number.isFinite(mosMilli)) throw new Error(`bad MOS at data row ${rowNumber}`);
    rowNumbers.push(rowNumber);
    valuesMilli.push(mosMilli);
  }
  const indicators = valuesMilli.map((m) => (m > POOR_THRESHOLD_MILLI ? 1 : 0));
  return { validRows, rowNumbers, valuesMilli, indicators };
}

// ---- Case 3: WebRTC-QoE inter-condition ACR gap (SUB) ---------------------
// Each subject rated all 15 test conditions. The verified statement subtracts
// the 20 encrypted worst-condition ratings from the panel sum of the
// unimpaired condition, so the released value is the aggregate ACR loss
// caused by the impairments. The subtracted operands are per-owner records.
function webrtcAcrGap() {
  if (!fs.existsSync(WEBRTC_CSV)) return null;
  const raw = fs.readFileSync(WEBRTC_CSV, "utf8").trim().split(/\r?\n/);
  const header = parseCsvLine(raw[0]).map((h) => h.trim());
  const userCols = header
    .map((h, i) => ({ h, i }))
    .filter(({ h }) => /^User\d+$/.test(h))
    .sort((a, b) => Number(a.h.slice(4)) - Number(b.h.slice(4)));
  const rows = raw.slice(1).map(parseCsvLine).map((r) => ({
    tc: Number(r[0]), delay: Number(r[1]), jitter: Number(r[2]), loss: Number(r[3]),
    ratings: userCols.map(({ i }) => Number(r[i])),
  }));
  const clean = rows.find((r) => r.delay === 0 && r.jitter === 0 && r.loss === 0);
  const worst = rows.reduce((a, r) =>
    r.delay + r.jitter + r.loss * 100 > a.delay + a.jitter + a.loss * 100 ? r : a
  );
  if (!clean) return null;
  const cleanSum = clean.ratings.reduce((a, b) => a + b, 0);
  const worstSum = worst.ratings.reduce((a, b) => a + b, 0);
  return {
    clean, worst, cleanSum, worstSum, gap: cleanSum - worstSum,
    users: userCols.map(({ h }) => h),
  };
}

const panel = stav360Panel();
const drive = driveTestIndicators();
const webrtc = webrtcAcrGap();

const cases = {
  generatedBy: "toolkit/examples/qoe/data/generate-linear-cases.mjs",
  note: "Plaintext values appear here because both sources are public research datasets and the emitter asserts exact TFHE decryption against them; in deployment each owner encrypts and signs locally.",
  cases: [
    {
      label: "stav360-session-mos-mean",
      op: "SUM",
      values: panel.values,
      tag_label: `stav360/${PANEL_VIDEO}/${PANEL_PATTERN}/n${PANEL_N}/epoch-1`,
      source: `STAV360 ratings, github.com/SLG-European-Projects/STAV360 Raw_Ratings.csv, doi:10.21227/BCPT-3904 (${PANEL_VIDEO}, ${PANEL_PATTERN}, first ${PANEL_N} users by id: ${panel.users.join("|")})`,
      interpretation: `session MOS mean = verified sum / ${PANEL_N} after decryption (N public)`,
    },
    {
      label: "drivetest-compliance-rate",
      op: "SUM",
      values: drive.indicators,
      tag_label: `drivetest/BS_1/${MOS_COLUMN}/stride16/epoch-1`,
      source: `VC-FHE/data/MOS_BS_1_Driver_PRB_10.csv (${MOS_COLUMN}, stride rows ${drive.rowNumbers.join("|")}, good <=> mosMilli > ${POOR_THRESHOLD_MILLI})`,
      interpretation: `verified sum = good-session count; compliant <=> count*1000 >= ${STRIDE_PANEL_N}*${TARGET_PERMILLE}`,
      metadata: {
        valuesMilli: drive.valuesMilli,
        rowNumbers: drive.rowNumbers,
        poorThresholdMilli: POOR_THRESHOLD_MILLI,
        targetPermille: TARGET_PERMILLE,
      },
    },
    ...(webrtc
      ? [
          {
            label: "webrtc-impairment-acr-gap",
            op: "SUB",
            values: [webrtc.cleanSum, ...webrtc.worst.ratings],
            tag_label: `webrtcqoe/TC${webrtc.clean.tc}-minus-TC${webrtc.worst.tc}/n${webrtc.worst.ratings.length}/epoch-1`,
            source: `WebRTC-QoE Subjective_results_dataset.csv, Zenodo 15836614 (TC${webrtc.clean.tc} = ${webrtc.clean.delay}/${webrtc.clean.jitter}/${webrtc.clean.loss} unimpaired, TC${webrtc.worst.tc} = ${webrtc.worst.delay} ms delay, ${webrtc.worst.jitter} ms jitter, ${webrtc.worst.loss}% loss; all ${webrtc.users.length} subjects: ${webrtc.users.join("|")})`,
            interpretation: `verified difference = aggregate ACR loss of the panel between the unimpaired and the worst condition (${webrtc.cleanSum} - ${webrtc.worstSum} = ${webrtc.gap}); the first operand is the previously verified unimpaired panel sum and the remaining operands are per-subject encrypted ratings`,
            metadata: {
              cleanCondition: `TC${webrtc.clean.tc}`,
              worstCondition: `TC${webrtc.worst.tc}`,
              cleanSum: webrtc.cleanSum,
              worstSum: webrtc.worstSum,
              gap: webrtc.gap,
            },
          },
        ]
      : []),
  ],
};

const outPath = path.join(here, "linear-cases.qoe.json");
fs.writeFileSync(outPath, JSON.stringify(cases, null, 2) + "\n");
console.log(`Wrote ${outPath}`);
console.log(`  case 1: ${cases.cases[0].label}  n=${panel.values.length}  values=${panel.values.join(",")}`);
console.log(`  case 2: ${cases.cases[1].label}  n=${drive.indicators.length}  indicators=${drive.indicators.join(",")}  goodCount=${drive.indicators.reduce((a, b) => a + b, 0)}`);
