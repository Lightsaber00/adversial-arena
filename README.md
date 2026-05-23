# 🔴 Adversarial Arena v2.0

> **RED vs. BLUE** — KI-gestützte Adversarial Training Simulation für AI Security Research

Eine browserbasierte Simulationsumgebung, in der ein **Red Team** (Angreifer) und ein **Blue Team** (Verteidiger) vollautomatisch gegeneinander trainieren — angetrieben von Claude (Anthropic) als KI-Engine. Angriffe und Verteidigungen werden auf Basis des **MITRE ATT&CK®-Frameworks** generiert, bewertet und über mehrere Generationen evolutionär optimiert.

---

## ✨ Features

| Feature | Beschreibung |
|---|---|
| 🧠 **Vector Memory** | Semantischer Angriffs-/Verteidigungs-Speicher mit Cosine-Similarity-Retrieval |
| 👥 **Population Training** | 4 Red- + 4 Blue-Agenten mit individuellem ELO und Spezialisierung |
| 📈 **Confidence-weighted ELO** | Margin of Victory bestimmt ELO-Änderung, nicht nur Sieg/Niederlage |
| 📊 **Real Metrics** | F1-Score, Precision, Recall, TP/FP/FN/TN pro Angriffsvektor |
| 🎯 **MITRE ATT&CK® Integration** | Angriffe gemappt auf TA0001–TA0043 (Initial Access, Exfil, Impact, ...) |
| 🧑‍🔬 **Human-in-the-Loop RLHF** | Forscher kann Feedback einreichen, das direkt in den nächsten Prompt einfließt |
| 🗺️ **Attack Space Map** | 2D-Cluster-Visualisierung aller Angriffe nach Taktik und Generation |
| ⚖️ **Blind Arbiter** | Unabhängiger KI-Schiedsrichter bewertet ohne Kenntnis von Red/Blue |
| 🔄 **Auto-Loop** | Vollautomatisches Training über beliebig viele Generationen |
| 📴 **Offline-Version** | Standalone-HTML ohne CDN-Abhängigkeiten |

---

## 🗂️ Dateien
adversarial-arena.html          # Online-Version (lädt React/Babel via CDN)
adversarial-arena-offline.html  # Offline-Version (alle Dependencies eingebettet)
adversarial-arena-v2.jsx        # React-Quellcode (JSX, für eigene Builds)
Adversial-Arena.md              # Konzept: AutoGen-basierte Python-Implementierung

---

## 🚀 Quickstart

### Option A — Online (empfohlen)
1. `adversarial-arena.html` im Browser öffnen (Chrome/Firefox/Edge)
2. Eigenen **Anthropic API-Key** eingeben (`sk-ant-...`)
3. **RUNDE** klicken oder **AUTO** aktivieren

### Option B — Offline (kein Internet nötig)
1. `adversarial-arena-offline.html` im Browser öffnen
2. API-Key eingeben → starten

### Option C — React-Projekt einbinden
```bash
# adversarial-arena-v2.jsx als Komponente importieren
import AdversarialArenaV2 from './adversarial-arena-v2'
