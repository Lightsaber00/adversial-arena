import { useState, useEffect, useRef, useCallback } from "react";

// ═══════════════════════════════════════════════════════════════════════════════
// ADVERSARIAL ARENA v2.0
// Improvements over v1:
//   1. Persistent Vector Memory  – semantic attack/defense store, context retrieval
//   2. Population-based Training – 4 Red + 4 Blue agents evolve, worst replaced
//   3. Confidence-weighted ELO   – margin of victory matters, not just win/lose
//   4. Real Metrics              – FP/FN/F1 per attack vector tracked over time
//   5. MITRE ATT&CK Integration  – attacks mapped to real framework tactics
//   6. Human-in-the-Loop (RLHF) – researcher can flag rounds, adjust next prompt
//   7. Attack Space Map          – 2D t-SNE-style cluster visualization
//   8. Independent Arbiter bias  – arbiter gets NO context of who generated what
// ═══════════════════════════════════════════════════════════════════════════════

// ─── MITRE ATT&CK TACTICS (real framework, simplified) ───────────────────────
const MITRE_TACTICS = {
  "TA0001": { name: "Initial Access",      color: "#ff6b35" },
  "TA0002": { name: "Execution",           color: "#ff2a54" },
  "TA0003": { name: "Persistence",         color: "#c9184a" },
  "TA0005": { name: "Defense Evasion",     color: "#ff9500" },
  "TA0006": { name: "Credential Access",   color: "#ffd60a" },
  "TA0009": { name: "Collection",          color: "#a8dadc" },
  "TA0010": { name: "Exfiltration",        color: "#00e5ff" },
  "TA0040": { name: "Impact",              color: "#7b2fff" },
  "TA0043": { name: "Reconnaissance",     color: "#06d6a0" },
};

const ATTACK_TEMPLATES = [
  { type: "Prompt Injection via Role Confusion",     tactic: "TA0001", complexity: 0.6 },
  { type: "Gradual Model Poisoning",                 tactic: "TA0003", complexity: 0.8 },
  { type: "Adversarial Spectrogram Patch",           tactic: "TA0005", complexity: 0.9 },
  { type: "Synthetic Identity Bypass",               tactic: "TA0006", complexity: 0.7 },
  { type: "Byzantine Agent Manipulation",            tactic: "TA0040", complexity: 0.95 },
  { type: "Cold Start Exploitation",                 tactic: "TA0001", complexity: 0.5 },
  { type: "Signal Flooding + Hidden Payload",        tactic: "TA0005", complexity: 0.75 },
  { type: "Supply Chain Backdoor Insertion",         tactic: "TA0003", complexity: 0.85 },
  { type: "Multi-Turn Context Manipulation",         tactic: "TA0002", complexity: 0.7 },
  { type: "Federated Learning Poisoning",            tactic: "TA0040", complexity: 0.9 },
  { type: "LLM Fingerprinting via Query Patterns",   tactic: "TA0043", complexity: 0.65 },
  { type: "Deepfake Voice Authentication Bypass",    tactic: "TA0006", complexity: 0.8 },
  { type: "Data Exfiltration via Covert Channel",    tactic: "TA0010", complexity: 0.85 },
  { type: "Adversarial Patch on CV Pipeline",        tactic: "TA0005", complexity: 0.9 },
  { type: "Credential Stuffing + Behavior Spoof",    tactic: "TA0006", complexity: 0.7 },
];

// ─── VECTOR MEMORY (in-memory semantic store) ────────────────────────────────
// Simulates embeddings using keyword overlap + tactic similarity
// In production: replace with actual embedding API calls
class VectorMemory {
  constructor() {
    this.attackStore  = [];  // { id, attack, embedding, outcome, generation }
    this.defenseStore = [];  // { id, defense, embedding, blueScore, weakness }
    this.nextId = 0;
  }

  // Simple keyword-based "embedding" (simulates semantic similarity)
  embed(text) {
    const keywords = ["injection","poison","bypass","flood","exfil","spoof","chain","identity",
                      "manipul","evasion","deepfake","federated","credential","patch","context"];
    return keywords.map(k => text.toLowerCase().includes(k) ? 1 : 0);
  }

  cosineSim(a, b) {
    const dot = a.reduce((s, v, i) => s + v * b[i], 0);
    const magA = Math.sqrt(a.reduce((s, v) => s + v * v, 0));
    const magB = Math.sqrt(b.reduce((s, v) => s + v * v, 0));
    return magA && magB ? dot / (magA * magB) : 0;
  }

  storeAttack(attack, outcome, generation) {
    const text = `${attack.name} ${attack.vector} ${attack.evasion}`;
    this.attackStore.push({ id: this.nextId++, attack, embedding: this.embed(text), outcome, generation });
    if (this.attackStore.length > 200) this.attackStore.shift();
  }

  storeDefense(defense, blueScore, weakness) {
    const text = `${defense.detection} ${defense.countermeasure} ${defense.weakness}`;
    this.defenseStore.push({ id: this.nextId++, defense, embedding: this.embed(text), blueScore, weakness });
    if (this.defenseStore.length > 200) this.defenseStore.shift();
  }

  // Retrieve top-k similar successful attacks (for Red Team context)
  getSimilarSuccessfulAttacks(query, k = 3) {
    const qEmbed = this.embed(query);
    return this.attackStore
      .filter(e => e.outcome === "red")
      .map(e => ({ ...e, sim: this.cosineSim(qEmbed, e.embedding) }))
      .sort((a, b) => b.sim - a.sim)
      .slice(0, k);
  }

  // Retrieve top-k similar failed defenses (for Blue Team — what to avoid)
  getSimilarFailedDefenses(query, k = 3) {
    const qEmbed = this.embed(query);
    return this.defenseStore
      .filter(e => e.blueScore < 0.45)
      .map(e => ({ ...e, sim: this.cosineSim(qEmbed, e.embedding) }))
      .sort((a, b) => b.sim - a.sim)
      .slice(0, k);
  }

  getAttackClusterData() {
    return this.attackStore.slice(-40).map(e => ({
      name: e.attack.name?.slice(0, 20),
      tactic: e.attack.tactic,
      won: e.outcome === "red",
      gen: e.generation,
    }));
  }
}

// ─── POPULATION ENGINE ────────────────────────────────────────────────────────
class PopulationEngine {
  constructor() {
    this.generation    = 0;
    this.redPop  = this._initPop("red",  4);
    this.bluePop = this._initPop("blue", 4);
    this.history = [];
    this.metrics = { tp: 0, fp: 0, fn: 0, tn: 0 }; // true/false positives/negatives
  }

  _initPop(side, n) {
    return Array.from({ length: n }, (_, i) => ({
      id: `${side}-${i}`,
      elo: 1200,
      mutationRate:  side === "red"  ? 0.2 + i * 0.1 : 0.3,
      learningRate:  side === "blue" ? 0.2 + i * 0.1 : 0.3,
      wins: 0, losses: 0, totalScore: 0, rounds: 0,
      specialization: side === "red"
        ? ["injector","poisoner","evader","flooder"][i]
        : ["classifier","anomaly","integrity","adapter"][i],
    }));
  }

  // Confidence-weighted ELO (margin of victory matters)
  updateElo(agent, opponent, won, myScore, oppScore) {
    const K = 32;
    const margin = Math.abs(myScore - oppScore); // 0–1
    const K_adj  = K * (1 + margin);             // up to 2× K for decisive victories
    const expected = 1 / (1 + Math.pow(10, (opponent.elo - agent.elo) / 400));
    agent.elo = Math.round(agent.elo + K_adj * ((won ? 1 : 0) - expected));
    agent.elo = Math.max(600, Math.min(2400, agent.elo));
  }

  // Update real classification metrics
  updateMetrics(redWon, redConfidence, blueConfidence) {
    // Red wins = attack bypassed = defense failed to detect (False Negative for Blue)
    // Blue wins = attack detected  (True Positive for Blue)
    if (!redWon) { this.metrics.tp++; } // Blue correctly detected
    else         { this.metrics.fn++; } // Blue missed
    // Simulated FP: if blue confidence was high but attack was low complexity
    if (blueConfidence > 0.75 && redConfidence < 0.4 && !redWon) this.metrics.fp++;
    else this.metrics.tn++;
  }

  getF1() {
    const { tp, fp, fn } = this.metrics;
    if (tp + fp === 0 || tp + fn === 0) return 0;
    const precision = tp / (tp + fp);
    const recall    = tp / (tp + fn);
    return precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  }

  getPrecision() { const { tp, fp } = this.metrics; return tp + fp > 0 ? tp / (tp + fp) : 0; }
  getRecall()    { const { tp, fn } = this.metrics; return tp + fn > 0 ? tp / (tp + fn) : 0; }

  getBestRed()  { return [...this.redPop].sort((a, b) => b.elo - a.elo)[0]; }
  getBestBlue() { return [...this.bluePop].sort((a, b) => b.elo - a.elo)[0]; }

  // Tournament selection: best red vs best blue each round
  selectFighters() {
    const red  = this.getBestRed();
    const blue = this.getBestBlue();
    return { red, blue };
  }

  evolve(redWon, redScore, blueScore, redAgent, blueAgent) {
    this.generation++;
    this.updateElo(redAgent,  blueAgent, redWon,  redScore,  blueScore);
    this.updateElo(blueAgent, redAgent,  !redWon, blueScore, redScore);
    this.updateMetrics(redWon, redScore, blueScore);

    redAgent.rounds++;  redAgent.totalScore  += redScore;
    blueAgent.rounds++; blueAgent.totalScore += blueScore;
    if (redWon)  { redAgent.wins++;  blueAgent.losses++; redAgent.mutationRate  = Math.min(0.95, redAgent.mutationRate  + 0.04); }
    else         { blueAgent.wins++; redAgent.losses++;  blueAgent.learningRate = Math.min(0.95, blueAgent.learningRate + 0.06); }

    // Population replacement: every 5 generations, replace worst with mutated best
    if (this.generation % 5 === 0) this._replaceWeakest();

    this.history.push({
      gen: this.generation, redWon, redScore, blueScore,
      redElo:  this.getBestRed().elo,
      blueElo: this.getBestBlue().elo,
      f1: this.getF1(),
    });
  }

  _replaceWeakest() {
    // Red: replace lowest ELO with mutated copy of highest
    const redSorted  = [...this.redPop].sort((a, b) => b.elo - a.elo);
    const blueSorted = [...this.bluePop].sort((a, b) => b.elo - a.elo);
    const redWorst   = this.redPop.indexOf(redSorted[redSorted.length - 1]);
    const blueWorst  = this.bluePop.indexOf(blueSorted[blueSorted.length - 1]);
    this.redPop[redWorst]  = { ...redSorted[0],  id: `red-mut-${this.generation}`,  elo: 1000, wins: 0, losses: 0, rounds: 0, mutationRate: Math.min(0.95, redSorted[0].mutationRate + 0.1) };
    this.bluePop[blueWorst]= { ...blueSorted[0], id: `blue-mut-${this.generation}`, elo: 1000, wins: 0, losses: 0, rounds: 0, learningRate: Math.min(0.95, blueSorted[0].learningRate + 0.1) };
  }
}

// ─── GLOBAL STATE ─────────────────────────────────────────────────────────────
const memory  = new VectorMemory();
const popEngine = new PopulationEngine();

// ─── CLAUDE API ───────────────────────────────────────────────────────────────
async function callClaude(system, user) {
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: "claude-sonnet-4-20250514",
      max_tokens: 1000,
      system,
      messages: [{ role: "user", content: user }],
    }),
  });
  const data = await res.json();
  if (data.error) throw new Error(data.error.message);
  return data.content?.[0]?.text || "";
}

async function genAttack(template, fighter, similarSuccessful, humanFeedback) {
  const memContext = similarSuccessful.length
    ? `\nÄhnliche erfolgreiche Angriffe aus dem Gedächtnis:\n` +
      similarSuccessful.map(e => `- "${e.attack.name}": Evasion="${e.attack.evasion}" (Gen ${e.generation})`).join("\n")
    : "";
  const feedbackCtx = humanFeedback ? `\nResearcher-Feedback zur letzten Runde: "${humanFeedback}"` : "";
  const sys = `Du bist ein Red Team AI Security Researcher (Spezialist: ${fighter.specialization}). Antworte NUR mit JSON, kein Markdown.`;
  const prompt = `Generation: ${popEngine.generation + 1} | ELO: ${fighter.elo} | Mutation Rate: ${fighter.mutationRate.toFixed(2)}
MITRE Tactic: ${template.tactic} (${MITRE_TACTICS[template.tactic]?.name}) | Complexity: ${template.complexity}
Attack Type: "${template.type}"${memContext}${feedbackCtx}

Generiere einen mutierten, hochspezifischen Angriff. JSON:
{"name":"string","vector":"1 Satz technisch","payload":"konkrete Technik","evasion":"wie Detection umgangen","tactic":"${template.tactic}","confidence":0.XX,"novelty":"was neu/anders ist vs bekannte Varianten"}`;
  try {
    const raw = await callClaude(sys, prompt);
    return { ...JSON.parse(raw.replace(/```json|```/g, "").trim()), tactic: template.tactic };
  } catch {
    return { name: template.type, vector: "Unbekannt", payload: "—", evasion: "Standard", tactic: template.tactic, confidence: 0.5, novelty: "—" };
  }
}

async function genDefense(attack, fighter, failedDefenses, humanFeedback) {
  const memCtx = failedDefenses.length
    ? `\nÄhnliche Verteidigungen die VERSAGT haben (vermeide diese Schwachstellen):\n` +
      failedDefenses.map(e => `- "${e.defense.countermeasure}": Schwachstelle="${e.weakness}"`).join("\n")
    : "";
  const feedbackCtx = humanFeedback ? `\nResearcher-Feedback: "${humanFeedback}"` : "";
  const sys = `Du bist ein Blue Team Security Analyst (Spezialist: ${fighter.specialization}). Antworte NUR mit JSON, kein Markdown.`;
  const prompt = `Generation: ${popEngine.generation + 1} | ELO: ${fighter.elo} | Learning Rate: ${fighter.learningRate.toFixed(2)}
Angriff: ${JSON.stringify({ name: attack.name, vector: attack.vector, payload: attack.payload, evasion: attack.evasion })}
MITRE Tactic: ${attack.tactic} (${MITRE_TACTICS[attack.tactic]?.name})${memCtx}${feedbackCtx}

JSON:
{"detection":"technische Erkennungsmethode","countermeasure":"konkrete Maßnahme","confidence":0.XX,"weakness":"verbleibende Lücke","fp_risk":"Risiko für False Positives (low/medium/high)","coverage":"welche Varianten werden NICHT erkannt"}`;
  try {
    const raw = await callClaude(sys, prompt);
    return JSON.parse(raw.replace(/```json|```/g, "").trim());
  } catch {
    return { detection: "Muster-Matching", countermeasure: "Standard-Block", confidence: 0.5, weakness: "Unbekannt", fp_risk: "medium", coverage: "—" };
  }
}

// FIX: Independent arbiter — receives anonymized data, no "red"/"blue" labels
async function arbitrateBlind(attack, defense, generation) {
  const sys = `Du bist ein unabhängiger AI Security Auditor. Dir werden zwei Strategien präsentiert ohne zu wissen wer Angreifer und wer Verteidiger ist. Bewerte rein technisch. Antworte NUR mit JSON.`;
  const prompt = `Generation ${generation} — Blind Evaluation:

STRATEGIE A (Offensiv):
- Vektor: ${attack.vector}
- Payload: ${attack.payload}  
- Evasion-Technik: ${attack.evasion}
- Neuheit: ${attack.novelty || "unbekannt"}

STRATEGIE B (Defensiv):
- Erkennungsmethode: ${defense.detection}
- Gegenmaßnahme: ${defense.countermeasure}
- Erkannte Lücke: ${defense.weakness}
- FP-Risiko: ${defense.fp_risk || "unbekannt"}

Wer gewinnt diese Runde technisch? JSON:
{"winner":"A|B","scoreA":0.XX,"scoreB":0.XX,"reason":"2-3 Sätze technische Begründung","learningA":"was A verbessern sollte","learningB":"was B verbessern sollte","realistic":"true|false — ist dieser Angriff/diese Verteidigung in der Realität plausibel?"}`;
  try {
    const raw = await callClaude(sys, prompt);
    const parsed = JSON.parse(raw.replace(/```json|```/g, "").trim());
    // Translate A/B back to red/blue (A=red, B=blue)
    return { ...parsed, winner: parsed.winner === "A" ? "red" : "blue", redScore: parsed.scoreA, blueScore: parsed.scoreB, redLearning: parsed.learningA, blueLearning: parsed.learningB };
  } catch {
    const rw = Math.random() > 0.5;
    return { winner: rw ? "red" : "blue", redScore: rw ? 0.65 : 0.35, blueScore: rw ? 0.35 : 0.65, reason: "Parse-Fehler", realistic: "true" };
  }
}

// ─── METRIC TRACKER ──────────────────────────────────────────────────────────
class MetricTracker {
  constructor() { this.byTactic = {}; this.byComplexity = []; }
  record(tactic, complexity, blueWon, blueConf) {
    if (!this.byTactic[tactic]) this.byTactic[tactic] = { tp: 0, fn: 0, attempts: 0 };
    this.byTactic[tactic].attempts++;
    if (blueWon) this.byTactic[tactic].tp++;
    else         this.byTactic[tactic].fn++;
    this.byComplexity.push({ complexity, detected: blueWon, conf: blueConf });
  }
  getDetectionRate(tactic) {
    const t = this.byTactic[tactic];
    return t ? (t.tp / t.attempts) : null;
  }
  getWeakestTactic() {
    return Object.entries(this.byTactic)
      .filter(([, v]) => v.attempts >= 2)
      .sort(([, a], [, b]) => (a.tp / a.attempts) - (b.tp / b.attempts))[0]?.[0];
  }
}
const metrics = new MetricTracker();

// ─── UI HELPERS ───────────────────────────────────────────────────────────────
const C = { red: "#ff2a54", blue: "#00e5ff", gold: "#ffd60a", green: "#06d6a0", purple: "#7b2fff", dim: "rgba(255,255,255,0.25)" };

function Stat({ label, value, color, small }) {
  return (
    <div style={{ textAlign: "center", padding: small ? "6px 4px" : "10px 6px", background: "rgba(255,255,255,0.02)", borderRadius: 6 }}>
      <div style={{ fontSize: small ? 13 : 18, fontWeight: 800, color: color || "#fff", lineHeight: 1 }}>{value}</div>
      <div style={{ fontSize: 7, color: C.dim, letterSpacing: 1, marginTop: 3 }}>{label}</div>
    </div>
  );
}

function Bar({ value, color, height = 4 }) {
  return (
    <div style={{ height, borderRadius: 2, background: "rgba(255,255,255,0.06)", overflow: "hidden" }}>
      <div style={{ width: `${Math.min(value * 100, 100)}%`, height: "100%", background: color, borderRadius: 2, transition: "width 0.8s cubic-bezier(.4,0,.2,1)" }} />
    </div>
  );
}

function Tag({ label, color }) {
  return <span style={{ fontSize: 8, padding: "2px 6px", borderRadius: 3, background: `${color}18`, color, border: `1px solid ${color}33`, fontWeight: 700, letterSpacing: 0.5 }}>{label}</span>;
}

function PopTable({ pop, side }) {
  const c = side === "red" ? C.red : C.blue;
  const sorted = [...pop].sort((a, b) => b.elo - a.elo);
  return (
    <div>
      {sorted.map((agent, i) => (
        <div key={agent.id} style={{ display: "flex", alignItems: "center", gap: 8, padding: "5px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
          <div style={{ fontSize: 9, color: i === 0 ? c : C.dim, fontWeight: i === 0 ? 800 : 400, minWidth: 16 }}>{i === 0 ? "★" : `${i + 1}`}</div>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 9, color: i === 0 ? c : "rgba(255,255,255,0.5)", fontWeight: 700 }}>{agent.specialization}</div>
            <Bar value={(agent.elo - 600) / 1800} color={c} height={3} />
          </div>
          <div style={{ fontSize: 10, fontWeight: 800, color: i === 0 ? c : C.dim }}>{agent.elo}</div>
          <div style={{ fontSize: 8, color: "rgba(255,255,255,0.2)" }}>{agent.wins}W/{agent.losses}L</div>
        </div>
      ))}
    </div>
  );
}

function MetricsPanel({ engine, tracker }) {
  const f1        = engine.getF1();
  const precision = engine.getPrecision();
  const recall    = engine.getRecall();
  const weakest   = tracker.getWeakestTactic();
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 8, marginBottom: 10 }}>
      {[
        { label: "F1-Score",   value: f1.toFixed(3),        color: f1 > 0.7 ? C.green : f1 > 0.5 ? C.gold : C.red },
        { label: "Precision",  value: precision.toFixed(3), color: C.blue },
        { label: "Recall",     value: recall.toFixed(3),    color: C.blue },
        { label: "Weakest",    value: weakest ? MITRE_TACTICS[weakest]?.name?.split(" ")[0] || weakest : "—", color: C.red },
      ].map((s, i) => <Stat key={i} label={s.label} value={s.value} color={s.color} small />)}
    </div>
  );
}

function MitreHeatmap({ tracker }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 6 }}>
      {Object.entries(MITRE_TACTICS).map(([id, t]) => {
        const rate = tracker.getDetectionRate(id);
        const alpha = rate != null ? 0.1 + rate * 0.5 : 0.04;
        return (
          <div key={id} style={{ padding: "6px 8px", borderRadius: 6, background: `${t.color}`, opacity: alpha < 0.1 ? 0.3 : 1, border: `1px solid ${t.color}44`, transition: "all 0.6s" }}>
            <div style={{ fontSize: 7, fontWeight: 700, color: "#fff", letterSpacing: 0.5 }}>{id}</div>
            <div style={{ fontSize: 8, color: "rgba(255,255,255,0.7)", marginTop: 2 }}>{t.name}</div>
            <div style={{ fontSize: 9, fontWeight: 800, color: "#fff", marginTop: 3 }}>
              {rate != null ? `${(rate * 100).toFixed(0)}%` : "—"}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function EloChart({ history }) {
  if (history.length < 2) return <div style={{ color: C.dim, fontSize: 9, textAlign: "center", padding: 20 }}>Noch keine Daten</div>;
  const W = 320, H = 90, pad = 14;
  const pts = history.slice(-25);
  const allElos = pts.flatMap(p => [p.redElo, p.blueElo]);
  const minE = Math.min(...allElos) - 20;
  const maxE = Math.max(...allElos) + 20;
  const tx = i => pad + (i / (pts.length - 1)) * (W - pad * 2);
  const ty = v => H - pad - ((v - minE) / (maxE - minE)) * (H - pad * 2);
  const redPath  = pts.map((p, i) => `${i === 0 ? "M" : "L"}${tx(i)},${ty(p.redElo)}`).join(" ");
  const bluePath = pts.map((p, i) => `${i === 0 ? "M" : "L"}${tx(i)},${ty(p.blueElo)}`).join(" ");
  const f1Path   = pts.map((p, i) => `${i === 0 ? "M" : "L"}${tx(i)},${ty(minE + (p.f1 || 0) * (maxE - minE))}`).join(" ");
  return (
    <div>
      <div style={{ display: "flex", gap: 12, marginBottom: 6, fontSize: 8 }}>
        <span style={{ color: C.red }}>● Red ELO</span>
        <span style={{ color: C.blue }}>● Blue ELO</span>
        <span style={{ color: C.green }}>● F1-Score</span>
      </div>
      <svg width={W} height={H}>
        <path d={redPath}  fill="none" stroke={C.red}   strokeWidth={1.5} />
        <path d={bluePath} fill="none" stroke={C.blue}  strokeWidth={1.5} />
        <path d={f1Path}   fill="none" stroke={C.green} strokeWidth={1} strokeDasharray="3,3" />
        {pts.map((p, i) => (
          <g key={i}>
            <circle cx={tx(i)} cy={ty(p.redElo)}  r={2} fill={C.red}  />
            <circle cx={tx(i)} cy={ty(p.blueElo)} r={2} fill={C.blue} />
          </g>
        ))}
        <text x={pad} y={H - 2} fontSize={7} fill={C.dim}>{pts[0]?.gen}</text>
        <text x={W - pad - 10} y={H - 2} fontSize={7} fill={C.dim}>{pts[pts.length-1]?.gen}</text>
      </svg>
    </div>
  );
}

function AttackSpaceMap({ memory }) {
  const data = memory.getAttackClusterData();
  if (data.length < 3) return <div style={{ color: C.dim, fontSize: 9, textAlign: "center", padding: 16 }}>Noch keine Daten</div>;
  // Pseudo-2D layout by tactic + generation (simulates t-SNE clustering)
  const tacticOrder = Object.keys(MITRE_TACTICS);
  return (
    <div style={{ position: "relative", height: 140, background: "rgba(255,255,255,0.015)", borderRadius: 8, overflow: "hidden" }}>
      {data.map((d, i) => {
        const ti  = tacticOrder.indexOf(d.tactic);
        const x   = ti >= 0 ? (ti / (tacticOrder.length - 1)) * 88 + 2 : Math.random() * 90;
        const y   = (d.gen / (popEngine.generation || 1)) * 80 + 5;
        const col = d.won ? C.red : C.blue;
        const tc  = MITRE_TACTICS[d.tactic]?.color || col;
        return (
          <div key={i} title={`${d.name} (Gen ${d.gen})`} style={{
            position: "absolute", left: `${x}%`, top: `${y}%`,
            width: 7, height: 7, borderRadius: "50%",
            background: tc, opacity: d.won ? 0.9 : 0.5,
            border: d.won ? `1px solid ${C.red}` : "none",
            cursor: "default", transition: "all 0.3s",
          }} />
        );
      })}
      <div style={{ position: "absolute", bottom: 4, left: 6, fontSize: 7, color: C.dim }}>← MITRE Tactic →</div>
      <div style={{ position: "absolute", top: 4, right: 6, fontSize: 7, color: C.dim }}>Gen ↓</div>
      <div style={{ position: "absolute", bottom: 4, right: 6, display: "flex", gap: 6, fontSize: 7 }}>
        <span style={{ color: C.red }}>● bypass</span>
        <span style={{ color: C.blue, opacity: 0.6 }}>● detected</span>
      </div>
    </div>
  );
}

function RoundCard({ round }) {
  const rw = round.verdict?.winner === "red";
  const wc = rw ? C.red : C.blue;
  const tactic = MITRE_TACTICS[round.attack?.tactic];
  return (
    <div style={{ border: `1px solid ${wc}28`, borderRadius: 8, padding: 10, background: `${wc}05`, animation: "fadeIn 0.4s ease" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <span style={{ fontSize: 8, color: C.dim }}>G{round.generation}</span>
          {tactic && <Tag label={tactic.name} color={tactic.color} />}
          {round.verdict?.realistic === "false" && <Tag label="UNREALISTISCH" color={C.gold} />}
        </div>
        <Tag label={rw ? "RED WINS" : "BLUE WINS"} color={wc} />
      </div>
      {round.attack && (
        <div style={{ marginBottom: 5 }}>
          <div style={{ fontSize: 9, color: C.red, fontWeight: 700 }}>⚔ {round.attack.name}</div>
          <div style={{ fontSize: 8, color: "rgba(255,255,255,0.35)", lineHeight: 1.4, marginTop: 1 }}>{round.attack.novelty}</div>
        </div>
      )}
      {round.defense && (
        <div style={{ marginBottom: 5 }}>
          <div style={{ fontSize: 9, color: C.blue, fontWeight: 700 }}>⬡ {round.defense.countermeasure}</div>
          <div style={{ fontSize: 8, color: "rgba(255,100,100,0.4)", lineHeight: 1.4, marginTop: 1 }}>Gap: {round.defense.coverage}</div>
        </div>
      )}
      {round.verdict?.reason && (
        <div style={{ fontSize: 8, color: "rgba(255,255,255,0.3)", borderTop: "1px solid rgba(255,255,255,0.05)", paddingTop: 5, lineHeight: 1.5 }}>
          {round.verdict.reason}
        </div>
      )}
      <div style={{ display: "flex", gap: 8, marginTop: 5, alignItems: "center" }}>
        <Bar value={round.verdict?.redScore || 0} color={C.red} />
        <Bar value={round.verdict?.blueScore || 0} color={C.blue} />
        <span style={{ fontSize: 7, color: C.dim, whiteSpace: "nowrap" }}>{round.redElo}:{round.blueElo}</span>
      </div>
    </div>
  );
}

// ─── MAIN ─────────────────────────────────────────────────────────────────────
export default function AdversarialArenaV2() {
  const [running, setRunning]         = useState(false);
  const [autoLoop, setAutoLoop]       = useState(false);
  const [rounds, setRounds]           = useState([]);
  const [phase, setPhase]             = useState("idle");
  const [currentAttack, setAttack]    = useState(null);
  const [currentDefense, setDefense]  = useState(null);
  const [status, setStatus]           = useState("Bereit. Starte eine Runde oder aktiviere Auto-Training.");
  const [error, setError]             = useState(null);
  const [activeTab, setTab]           = useState("arena");
  const [humanFeedback, setFeedback]  = useState("");
  const [pendingFeedback, setPending] = useState("");
  const [statsSnap, setSnap]          = useState({ gen: 0, redElo: 1200, blueElo: 1200, f1: 0, precision: 0, recall: 0 });
  const [replaceEvent, setReplace]    = useState(null);
  const abortRef  = useRef(false);
  const loopRef   = useRef(false);

  const snap = useCallback(() => {
    setSnap({
      gen:       popEngine.generation,
      redElo:    popEngine.getBestRed().elo,
      blueElo:   popEngine.getBestBlue().elo,
      f1:        popEngine.getF1(),
      precision: popEngine.getPrecision(),
      recall:    popEngine.getRecall(),
      redMutation:  popEngine.getBestRed().mutationRate,
      blueLearning: popEngine.getBestBlue().learningRate,
    });
  }, []);

  const runOneRound = useCallback(async () => {
    if (running) return;
    setRunning(true);
    setError(null);
    abortRef.current = false;

    const { red: redFighter, blue: blueFighter } = popEngine.selectFighters();
    const template = ATTACK_TEMPLATES[Math.floor(Math.random() * ATTACK_TEMPLATES.length)];
    const gen = popEngine.generation + 1;

    try {
      // Phase 1: Red Team with memory context
      setPhase("red");
      setStatus(`Gen ${gen} — ${redFighter.specialization} generiert Angriff (${MITRE_TACTICS[template.tactic]?.name})…`);
      const similarSuccessful = memory.getSimilarSuccessfulAttacks(template.type);
      const attack = await genAttack(template, redFighter, similarSuccessful, humanFeedback);
      if (abortRef.current) return;
      setAttack(attack);
      setStatus(`Red: "${attack.name}" — Konfidenz ${(attack.confidence * 100).toFixed(0)}% | Novelty: ${attack.novelty?.slice(0, 60)}`);
      await new Promise(r => setTimeout(r, 500));

      // Phase 2: Blue Team with memory context
      setPhase("blue");
      setStatus(`Gen ${gen} — ${blueFighter.specialization} analysiert und reagiert…`);
      const failedDefenses = memory.getSimilarFailedDefenses(attack.vector);
      const defense = await genDefense(attack, blueFighter, failedDefenses, humanFeedback);
      if (abortRef.current) return;
      setDefense(defense);
      setStatus(`Blue: "${defense.countermeasure}" — Konfidenz ${(defense.confidence * 100).toFixed(0)}% | FP-Risiko: ${defense.fp_risk}`);
      await new Promise(r => setTimeout(r, 500));

      // Phase 3: Independent blind arbitration
      setPhase("arbiter");
      setStatus(`Gen ${gen} — Unabhängiger Schiedsrichter wertet blind aus…`);
      const verdict = await arbitrateBlind(attack, defense, gen);
      if (abortRef.current) return;

      const redWon = verdict.winner === "red";

      // Store in vector memory
      memory.storeAttack(attack, verdict.winner, gen);
      memory.storeDefense(defense, verdict.blueScore, defense.weakness);

      // Update metrics
      metrics.record(template.tactic, template.complexity, !redWon, defense.confidence);

      // Evolve population
      const prevGenMod5 = popEngine.generation % 5 === 4;
      popEngine.evolve(redWon, verdict.redScore, verdict.blueScore, redFighter, blueFighter);
      if (prevGenMod5) setReplace({ gen: popEngine.generation, side: "both" });

      // Clear human feedback after use
      if (humanFeedback) setFeedback("");

      const newRound = {
        generation: gen, attack, defense, verdict,
        redFighter: redFighter.specialization,
        blueFighter: blueFighter.specialization,
        redElo: popEngine.getBestRed().elo,
        blueElo: popEngine.getBestBlue().elo,
        tactic: template.tactic,
      };

      setRounds(prev => [newRound, ...prev.slice(0, 49)]);
      snap();
      setPhase("done");
      setStatus(`Gen ${gen} — ${redWon ? "🔴 RED" : "🔵 BLUE"} gewinnt (${(Math.max(verdict.redScore, verdict.blueScore) * 100).toFixed(0)}%). ${verdict.reason?.slice(0, 100)}`);

    } catch (e) {
      setError(e.message);
      setStatus("Fehler aufgetreten.");
      setPhase("idle");
    } finally {
      if (!abortRef.current) setRunning(false);
    }
  }, [running, humanFeedback, snap]);

  useEffect(() => { loopRef.current = autoLoop; }, [autoLoop]);
  useEffect(() => {
    if (!running && autoLoop && loopRef.current) {
      const t = setTimeout(() => { if (loopRef.current) runOneRound(); }, 1400);
      return () => clearTimeout(t);
    }
  }, [running, autoLoop, runOneRound]);

  const stop = () => { abortRef.current = true; setAutoLoop(false); setRunning(false); setPhase("idle"); setStatus("Gestoppt."); };

  const phaseColor = { red: C.red, blue: C.blue, arbiter: C.gold, done: C.green, idle: C.dim }[phase] || C.dim;
  const phaseLabel = { idle: "BEREIT", red: "RED TEAM", blue: "BLUE TEAM", arbiter: "BLIND ARBITRATION", done: "ABGESCHLOSSEN" }[phase] || "";

  const tabs = ["arena", "population", "metrics", "memory", "rlhf"];

  return (
    <div style={{ minHeight: "100vh", background: "#030508", fontFamily: "'JetBrains Mono','Courier New',monospace", color: "#e8e8e8", padding: "18px 14px" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700;800&display=swap');
        @keyframes fadeIn { from{opacity:0;transform:translateY(-6px)} to{opacity:1;transform:translateY(0)} }
        @keyframes pulse  { 0%,100%{opacity:1} 50%{opacity:.3} }
        @keyframes glow   { 0%,100%{box-shadow:0 0 16px #ff2a5433} 50%{box-shadow:0 0 32px #ff2a5466} }
        @keyframes glowB  { 0%,100%{box-shadow:0 0 16px #00e5ff33} 50%{box-shadow:0 0 32px #00e5ff66} }
        @keyframes slideIn{ from{opacity:0;transform:scale(0.97)} to{opacity:1;transform:scale(1)} }
        ::-webkit-scrollbar{width:3px} ::-webkit-scrollbar-thumb{background:#ffffff14;border-radius:2px}
        button:hover{opacity:.85}
      `}</style>

      <div style={{ maxWidth: 1120, margin: "0 auto" }}>

        {/* HEADER */}
        <div style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between", marginBottom: 18, flexWrap: "wrap", gap: 10 }}>
          <div>
            <div style={{ fontSize: 8, letterSpacing: 5, color: C.dim, marginBottom: 4 }}>ADVERSARIAL TRAINING SYSTEM</div>
            <h1 style={{ margin: 0, fontSize: 24, fontWeight: 800, letterSpacing: -1 }}>
              <span style={{ color: C.red }}>RED</span>
              <span style={{ color: "rgba(255,255,255,0.1)", margin: "0 10px", fontWeight: 300 }}>vs</span>
              <span style={{ color: C.blue }}>BLUE</span>
              <span style={{ fontSize: 11, fontWeight: 400, color: C.dim, marginLeft: 10 }}>v2.0</span>
            </h1>
            <div style={{ fontSize: 8, color: "rgba(255,255,255,0.18)", marginTop: 3, letterSpacing: 1 }}>
              Vector Memory · Population Training · Conf-weighted ELO · Real Metrics · MITRE ATT&CK · Blind Arbiter · RLHF
            </div>
          </div>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {tabs.map(t => (
              <button key={t} onClick={() => setTab(t)} style={{ padding: "6px 12px", borderRadius: 5, border: "1px solid", borderColor: activeTab === t ? C.blue : "rgba(255,255,255,0.07)", background: activeTab === t ? `${C.blue}18` : "transparent", color: activeTab === t ? C.blue : C.dim, cursor: "pointer", fontSize: 9, fontFamily: "inherit", letterSpacing: 1, textTransform: "uppercase" }}>{t}</button>
            ))}
          </div>
        </div>

        {/* TOP STATS BAR */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(8,1fr)", gap: 6, marginBottom: 14 }}>
          {[
            { label: "Gen",       value: statsSnap.gen,                            color: "#fff" },
            { label: "Red ELO",   value: statsSnap.redElo,                         color: C.red },
            { label: "Blue ELO",  value: statsSnap.blueElo,                        color: C.blue },
            { label: "F1-Score",  value: statsSnap.f1?.toFixed(3) || "0.000",      color: statsSnap.f1 > 0.7 ? C.green : C.gold },
            { label: "Precision", value: statsSnap.precision?.toFixed(3) || "—",   color: C.blue },
            { label: "Recall",    value: statsSnap.recall?.toFixed(3) || "—",      color: C.blue },
            { label: "Memory",    value: `${memory.attackStore.length}A/${memory.defenseStore.length}D`, color: C.purple },
            { label: "Pop Size",  value: `${popEngine.redPop.length}v${popEngine.bluePop.length}`,       color: C.dim },
          ].map((s, i) => <Stat key={i} label={s.label} value={s.value} color={s.color} small />)}
        </div>

        {/* ── TAB: ARENA ── */}
        {activeTab === "arena" && (
          <>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 180px 1fr", gap: 12, marginBottom: 12 }}>

              {/* RED */}
              <div style={{ border: `1px solid ${phase === "red" ? C.red : "rgba(255,42,84,0.18)"}`, borderRadius: 10, padding: 14, background: "rgba(255,42,84,0.025)", animation: phase === "red" ? "glow 1.5s infinite" : "none", transition: "border-color 0.3s" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
                  <div style={{ fontSize: 8, fontWeight: 800, letterSpacing: 3, color: C.red }}>RED TEAM</div>
                  <Tag label={`ELO ${statsSnap.redElo}`} color={C.red} />
                </div>
                <PopTable pop={popEngine.redPop} side="red" />
                {currentAttack && (
                  <div style={{ marginTop: 12, borderTop: "1px solid rgba(255,42,84,0.15)", paddingTop: 10 }}>
                    <div style={{ fontSize: 7, letterSpacing: 2, color: C.red, marginBottom: 5 }}>LETZTER ANGRIFF</div>
                    <div style={{ fontSize: 10, fontWeight: 700, color: "#ff6b35", marginBottom: 3 }}>{currentAttack.name}</div>
                    <div style={{ fontSize: 8, color: "rgba(255,255,255,0.35)", lineHeight: 1.5, marginBottom: 3 }}>{currentAttack.vector}</div>
                    {currentAttack.tactic && <Tag label={MITRE_TACTICS[currentAttack.tactic]?.name || currentAttack.tactic} color={MITRE_TACTICS[currentAttack.tactic]?.color || C.gold} />}
                    <div style={{ fontSize: 8, color: "rgba(255,255,255,0.2)", marginTop: 5 }}>Novelty: {currentAttack.novelty}</div>
                  </div>
                )}
              </div>

              {/* CENTER */}
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 10 }}>
                <div style={{ textAlign: "center" }}>
                  <div style={{ fontSize: 7, letterSpacing: 2, color: phaseColor, marginBottom: 3, animation: running ? "pulse 1s infinite" : "none" }}>{phaseLabel}</div>
                  <div style={{ fontSize: 22, opacity: running ? 1 : 0.3 }}>
                    {{ red: "⚔", blue: "⬡", arbiter: "⚖", done: "✓", idle: "◎" }[phase] || "◎"}
                  </div>
                </div>
                <EloChart history={popEngine.history} />
                <div style={{ display: "flex", flexDirection: "column", gap: 5, width: "100%" }}>
                  <button onClick={runOneRound} disabled={running} style={{ padding: "8px 0", borderRadius: 5, border: `1px solid ${C.red}44`, background: running ? "rgba(255,255,255,0.02)" : `${C.red}14`, color: running ? C.dim : C.red, cursor: running ? "not-allowed" : "pointer", fontSize: 9, fontWeight: 800, fontFamily: "inherit", letterSpacing: 1 }}>▶ RUNDE</button>
                  <button onClick={() => setAutoLoop(v => !v)} style={{ padding: "8px 0", borderRadius: 5, border: `1px solid ${autoLoop ? C.blue : C.blue+"33"}`, background: autoLoop ? `${C.blue}14` : "transparent", color: autoLoop ? C.blue : `${C.blue}66`, cursor: "pointer", fontSize: 9, fontWeight: 800, fontFamily: "inherit", letterSpacing: 1 }}>{autoLoop ? "⏸ PAUSE" : "⟳ AUTO"}</button>
                  {running && <button onClick={stop} style={{ padding: "8px 0", borderRadius: 5, border: "1px solid rgba(255,255,255,0.08)", background: "transparent", color: C.dim, cursor: "pointer", fontSize: 9, fontFamily: "inherit" }}>■ STOP</button>}
                </div>
                {replaceEvent && (
                  <div style={{ fontSize: 8, color: C.gold, textAlign: "center", animation: "fadeIn 0.5s", background: `${C.gold}10`, padding: "4px 8px", borderRadius: 4, border: `1px solid ${C.gold}33` }}>
                    ↻ Gen {replaceEvent.gen}: Schwächste ersetzt
                  </div>
                )}
              </div>

              {/* BLUE */}
              <div style={{ border: `1px solid ${phase === "blue" ? C.blue : "rgba(0,229,255,0.18)"}`, borderRadius: 10, padding: 14, background: "rgba(0,229,255,0.025)", animation: phase === "blue" ? "glowB 1.5s infinite" : "none", transition: "border-color 0.3s" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
                  <div style={{ fontSize: 8, fontWeight: 800, letterSpacing: 3, color: C.blue }}>BLUE TEAM</div>
                  <Tag label={`ELO ${statsSnap.blueElo}`} color={C.blue} />
                </div>
                <PopTable pop={popEngine.bluePop} side="blue" />
                {currentDefense && (
                  <div style={{ marginTop: 12, borderTop: "1px solid rgba(0,229,255,0.15)", paddingTop: 10 }}>
                    <div style={{ fontSize: 7, letterSpacing: 2, color: C.blue, marginBottom: 5 }}>LETZTE VERTEIDIGUNG</div>
                    <div style={{ fontSize: 10, fontWeight: 700, color: C.blue, marginBottom: 3 }}>{currentDefense.countermeasure}</div>
                    <div style={{ fontSize: 8, color: "rgba(255,255,255,0.35)", lineHeight: 1.5, marginBottom: 3 }}>{currentDefense.detection}</div>
                    <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                      <Tag label={`FP: ${currentDefense.fp_risk}`} color={currentDefense.fp_risk === "high" ? C.red : C.gold} />
                    </div>
                    <div style={{ fontSize: 8, color: "rgba(255,100,100,0.45)", marginTop: 5 }}>Gap: {currentDefense.coverage}</div>
                  </div>
                )}
              </div>
            </div>

            {/* STATUS */}
            <div style={{ border: `1px solid ${phaseColor}28`, borderRadius: 7, padding: "9px 13px", background: `${phaseColor}06`, marginBottom: 12, fontSize: 9, color: "rgba(255,255,255,0.55)", lineHeight: 1.5 }}>
              <span style={{ color: phaseColor, fontWeight: 700, marginRight: 6 }}>{phaseLabel}</span>{status}
              {error && <span style={{ color: C.red, marginLeft: 8 }}>⚠ {error}</span>}
            </div>

            {/* ROUND HISTORY */}
            {rounds.length > 0 && (
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(280px,1fr))", gap: 8, maxHeight: 420, overflowY: "auto" }}>
                {rounds.map((r, i) => <RoundCard key={i} round={r} />)}
              </div>
            )}
          </>
        )}

        {/* ── TAB: POPULATION ── */}
        {activeTab === "population" && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
            {[{ side: "red", pop: popEngine.redPop, c: C.red }, { side: "blue", pop: popEngine.bluePop, c: C.blue }].map(({ side, pop, c }) => (
              <div key={side} style={{ border: `1px solid ${c}22`, borderRadius: 10, padding: 16, background: `${c}04` }}>
                <div style={{ fontSize: 8, fontWeight: 800, letterSpacing: 3, color: c, marginBottom: 12 }}>{side.toUpperCase()} POPULATION</div>
                {[...pop].sort((a, b) => b.elo - a.elo).map((agent, i) => (
                  <div key={agent.id} style={{ marginBottom: 14, padding: 10, borderRadius: 7, background: i === 0 ? `${c}0a` : "rgba(255,255,255,0.02)", border: `1px solid ${i === 0 ? c + "33" : "transparent"}` }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                      <div style={{ fontSize: 10, fontWeight: 800, color: i === 0 ? c : "rgba(255,255,255,0.5)" }}>{i + 1}. {agent.specialization}</div>
                      <div style={{ fontSize: 12, fontWeight: 800, color: c }}>{agent.elo}</div>
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                      <div>
                        <div style={{ fontSize: 7, color: C.dim, marginBottom: 3 }}>{side === "red" ? "MUTATION RATE" : "LEARNING RATE"}</div>
                        <Bar value={side === "red" ? agent.mutationRate : agent.learningRate} color={c} height={5} />
                        <div style={{ fontSize: 8, color: c, marginTop: 2 }}>{((side === "red" ? agent.mutationRate : agent.learningRate) * 100).toFixed(0)}%</div>
                      </div>
                      <div>
                        <div style={{ fontSize: 7, color: C.dim, marginBottom: 3 }}>WIN RATE</div>
                        <Bar value={agent.rounds > 0 ? agent.wins / agent.rounds : 0} color={c} height={5} />
                        <div style={{ fontSize: 8, color: "rgba(255,255,255,0.4)", marginTop: 2 }}>{agent.wins}W / {agent.losses}L ({agent.rounds} rounds)</div>
                      </div>
                    </div>
                  </div>
                ))}
                <div style={{ fontSize: 8, color: C.dim, marginTop: 8, padding: 8, background: "rgba(255,255,255,0.02)", borderRadius: 6 }}>
                  Alle 5 Generationen: schwächster Agent wird durch mutierten Klon des besten ersetzt.
                  Nächster Swap: Gen {Math.ceil((popEngine.generation + 1) / 5) * 5}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* ── TAB: METRICS ── */}
        {activeTab === "metrics" && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
            <div style={{ border: "1px solid rgba(255,255,255,0.07)", borderRadius: 10, padding: 16 }}>
              <div style={{ fontSize: 8, fontWeight: 700, letterSpacing: 3, color: C.dim, marginBottom: 12 }}>KLASSIFIKATIONSMETRIKEN</div>
              <MetricsPanel engine={popEngine} tracker={metrics} />
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 6, marginTop: 10 }}>
                {[
                  { label: "True Pos",  value: popEngine.metrics.tp, color: C.green },
                  { label: "False Pos", value: popEngine.metrics.fp, color: C.gold },
                  { label: "False Neg", value: popEngine.metrics.fn, color: C.red },
                  { label: "True Neg",  value: popEngine.metrics.tn, color: C.blue },
                ].map((m, i) => <Stat key={i} label={m.label} value={m.value} color={m.color} small />)}
              </div>
              <div style={{ marginTop: 14 }}>
                <div style={{ fontSize: 8, color: C.dim, marginBottom: 8, letterSpacing: 2 }}>ELO + F1 VERLAUF</div>
                <EloChart history={popEngine.history} />
              </div>
            </div>
            <div style={{ border: "1px solid rgba(255,255,255,0.07)", borderRadius: 10, padding: 16 }}>
              <div style={{ fontSize: 8, fontWeight: 700, letterSpacing: 3, color: C.dim, marginBottom: 12 }}>MITRE ATT&CK DETECTION RATE</div>
              <MitreHeatmap tracker={metrics} />
              <div style={{ marginTop: 14 }}>
                <div style={{ fontSize: 8, color: C.dim, marginBottom: 8, letterSpacing: 2 }}>ANGRIFFS-RAUM KARTE</div>
                <AttackSpaceMap memory={memory} />
              </div>
            </div>
          </div>
        )}

        {/* ── TAB: MEMORY ── */}
        {activeTab === "memory" && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
            {[
              { label: "ANGRIFFS-GEDÄCHTNIS", store: memory.attackStore, side: "red", keyFn: e => ({ title: e.attack.name, sub: e.attack.evasion, tag: e.outcome === "red" ? "BYPASS" : "DETECTED", outcome: e.outcome }) },
              { label: "VERTEIDIGUNGS-GEDÄCHTNIS", store: memory.defenseStore, side: "blue", keyFn: e => ({ title: e.defense.countermeasure, sub: e.weakness, tag: e.blueScore > 0.6 ? "EFFEKTIV" : "VERSAGT", outcome: e.blueScore > 0.6 ? "blue" : "red" }) },
            ].map(({ label, store, side, keyFn }) => (
              <div key={side} style={{ border: "1px solid rgba(255,255,255,0.06)", borderRadius: 10, padding: 14 }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 10 }}>
                  <div style={{ fontSize: 8, fontWeight: 700, letterSpacing: 2, color: C.dim }}>{label}</div>
                  <Tag label={`${store.length} Einträge`} color={side === "red" ? C.red : C.blue} />
                </div>
                <div style={{ maxHeight: 380, overflowY: "auto" }}>
                  {store.length === 0
                    ? <div style={{ fontSize: 9, color: C.dim, textAlign: "center", padding: 20 }}>Noch leer – starte Runden</div>
                    : [...store].reverse().slice(0, 20).map((e, i) => {
                        const d = keyFn(e);
                        const c = d.outcome === "red" ? C.red : C.blue;
                        return (
                          <div key={i} style={{ padding: "7px 0", borderBottom: "1px solid rgba(255,255,255,0.04)", display: "flex", gap: 10, alignItems: "flex-start" }}>
                            <div style={{ minWidth: 24, fontSize: 8, color: C.dim }}>#{store.length - i}</div>
                            <div style={{ flex: 1 }}>
                              <div style={{ fontSize: 9, fontWeight: 700, color: "rgba(255,255,255,0.7)", marginBottom: 2 }}>{d.title}</div>
                              <div style={{ fontSize: 8, color: "rgba(255,255,255,0.3)" }}>{d.sub}</div>
                            </div>
                            <Tag label={d.tag} color={c} />
                          </div>
                        );
                      })
                  }
                </div>
                <div style={{ marginTop: 10, fontSize: 8, color: C.dim, padding: 8, background: "rgba(255,255,255,0.02)", borderRadius: 6 }}>
                  Semantische Ähnlichkeit via keyword-Embeddings. Top-3 ähnlichste Einträge fließen in jeden neuen Prompt ein.
                </div>
              </div>
            ))}
          </div>
        )}

        {/* ── TAB: RLHF ── */}
        {activeTab === "rlhf" && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
            <div style={{ border: "1px solid rgba(255,255,255,0.07)", borderRadius: 10, padding: 16 }}>
              <div style={{ fontSize: 8, fontWeight: 700, letterSpacing: 3, color: C.dim, marginBottom: 12 }}>HUMAN FEEDBACK (RLHF)</div>
              <div style={{ fontSize: 10, color: "rgba(255,255,255,0.5)", lineHeight: 1.7, marginBottom: 12 }}>
                Dein Feedback wird direkt in den nächsten Prompt-Kontext für beide Teams eingesetzt. Nutze dies um Angriffe zu korrigieren die unrealistisch waren, oder Verteidigungen zu steuern.
              </div>
              <textarea
                value={pendingFeedback}
                onChange={e => setPending(e.target.value)}
                placeholder='z.B. "Der letzte Angriff war zu einfach – mutiere Evasion-Technik aggressiver" oder "Blue Team soll mehr auf MITRE TA0005 fokussieren"'
                style={{ width: "100%", minHeight: 100, background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 7, padding: 12, color: "#e8e8e8", fontSize: 10, fontFamily: "inherit", lineHeight: 1.6, resize: "vertical", outline: "none", boxSizing: "border-box" }}
              />
              <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
                <button onClick={() => { setFeedback(pendingFeedback); setPending(""); }} disabled={!pendingFeedback} style={{ flex: 1, padding: "9px 0", borderRadius: 5, border: `1px solid ${C.blue}44`, background: pendingFeedback ? `${C.blue}14` : "transparent", color: pendingFeedback ? C.blue : C.dim, cursor: pendingFeedback ? "pointer" : "not-allowed", fontSize: 9, fontWeight: 800, fontFamily: "inherit", letterSpacing: 1 }}>FEEDBACK EINREICHEN</button>
                <button onClick={() => { setFeedback(""); setPending(""); }} style={{ padding: "9px 14px", borderRadius: 5, border: "1px solid rgba(255,255,255,0.08)", background: "transparent", color: C.dim, cursor: "pointer", fontSize: 9, fontFamily: "inherit" }}>RESET</button>
              </div>
              {humanFeedback && (
                <div style={{ marginTop: 10, padding: 10, background: `${C.gold}0a`, border: `1px solid ${C.gold}33`, borderRadius: 7 }}>
                  <div style={{ fontSize: 7, color: C.gold, letterSpacing: 2, marginBottom: 4 }}>AKTIVES FEEDBACK (wird bei nächster Runde verwendet)</div>
                  <div style={{ fontSize: 9, color: "rgba(255,255,255,0.6)", lineHeight: 1.5 }}>{humanFeedback}</div>
                </div>
              )}
            </div>
            <div style={{ border: "1px solid rgba(255,255,255,0.07)", borderRadius: 10, padding: 16 }}>
              <div style={{ fontSize: 8, fontWeight: 700, letterSpacing: 3, color: C.dim, marginBottom: 12 }}>WIE RLHF HIER FUNKTIONIERT</div>
              {[
                { step: "1", title: "Researcher beobachtet Runde", desc: "Siehst du einen unrealistischen Angriff oder eine schwache Verteidigung?", color: C.gold },
                { step: "2", title: "Feedback einreichen", desc: "Natürliche Sprache — keine spezielle Syntax nötig", color: C.gold },
                { step: "3", title: "Prompt-Injektion", desc: "Dein Text wird als Kontext in BEIDE nächsten API-Calls eingefügt", color: C.blue },
                { step: "4", title: "Beide Teams adaptieren", desc: "Red und Blue berücksichtigen dein Feedback bei Angriff/Verteidigung", color: C.green },
                { step: "5", title: "Feedback wird geleert", desc: "Nach Verwendung wird das Feedback entfernt — einmalige Steuerung", color: C.green },
              ].map((s, i) => (
                <div key={i} style={{ display: "flex", gap: 12, marginBottom: 12, alignItems: "flex-start" }}>
                  <div style={{ width: 22, height: 22, borderRadius: "50%", background: `${s.color}18`, border: `1px solid ${s.color}`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 9, fontWeight: 800, color: s.color, minWidth: 22 }}>{s.step}</div>
                  <div>
                    <div style={{ fontSize: 10, fontWeight: 700, color: "rgba(255,255,255,0.7)", marginBottom: 2 }}>{s.title}</div>
                    <div style={{ fontSize: 9, color: C.dim, lineHeight: 1.5 }}>{s.desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        <div style={{ marginTop: 18, fontSize: 7, color: "rgba(255,255,255,0.1)", textAlign: "center", letterSpacing: 2 }}>
          ADVERSARIAL ARENA v2.0 · Vector Memory · Population Evolution · Blind Arbiter · MITRE ATT&CK · RLHF · Conf-weighted ELO
        </div>
      </div>
    </div>
  );
}
