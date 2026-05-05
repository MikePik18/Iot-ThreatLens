import os
import json
from io import BytesIO

import joblib
import pandas as pd
import xgboost as xgb
from dotenv import load_dotenv
from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from google import genai
from pydantic import BaseModel

load_dotenv(dotenv_path="../.env")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.environ.get("FRONTEND_URL", "http://localhost:3000")],
    allow_methods=["*"],
    allow_headers=["*"],
)

model = xgb.Booster()
model.load_model("xgb_model.ubj")
scaler = joblib.load("scaler.pkl")
encoders = joblib.load("encoders.pkl")

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

# in-memory store of the malicious dataframe from the last /analyze run
_malicious_df: pd.DataFrame | None = None

categorical_columns = ["proto", "service", "conn_state"]
numerical_columns = ["orig_bytes", "resp_bytes", "duration", "orig_pkts", "resp_pkts", "missed_bytes"]


def event(data):
    return f"data: {json.dumps(data)}\n\n"


def classify_all(df):
    # maps traffic features to IoT-23 attack names + severity
    # rules go low -> high priority so last match wins
    s = df["service"].str.lower().str.strip()
    p = df["proto"].str.lower().str.strip()
    c = df["conn_state"].str.upper().str.strip()

    atype = pd.Series("Attack", index=df.index, dtype=str)
    sev = pd.Series(2, index=df.index, dtype=int)

    def rule(mask, attack, severity_val):
        atype.loc[mask] = attack
        sev.loc[mask] = severity_val

    # low priority first, later rules override
    rule(c.isin(["REJ", "RSTOS0"]), "PartOfAHorizontalPortScan", 2)
    rule(p == "icmp", "PartOfAHorizontalPortScan", 2)
    rule(c.isin(["RSTO", "RSTR"]), "Okiru", 3)
    rule((p == "udp") & (c == "S0"), "DDoS", 3)
    rule(s == "dns", "C&C-HeartBeat", 3)
    rule(c == "SF", "C&C-HeartBeat", 3)
    rule((p == "tcp") & (c == "S0"), "PartOfAHorizontalPortScan-Attack", 3)
    rule(s == "ssh", "Mirai", 4)
    rule((s == "ssh") & (c == "SF"), "C&C-Mirai", 4)
    rule(s.isin(["http", "ssl", "https"]), "C&C-HeartBeat-Attack", 4)
    rule(s.isin(["http", "ssl", "https"]) & (c == "S0"), "DDoS", 4)
    rule(s.isin(["http", "ssl", "https"]) & (c == "SF"), "C&C-HeartBeat", 4)
    # IRC = classic Mirai C2, always critical
    rule(s == "irc", "C&C-Mirai", 5)
    # file transfers are always severity 5
    rule(s.isin(["ftp", "ftp-data", "sftp", "smb"]), "C&C-FileDownload", 5)
    rule(s.isin(["ftp", "ftp-data"]) & (c == "SF"), "FileDownload", 5)

    return atype, sev


def preprocess(df):
    df = df[categorical_columns + numerical_columns].copy()
    for col in categorical_columns:
        df[col] = df[col].fillna("Unknown").astype(str)
        le = encoders[col]
        df[col] = df[col].apply(
            lambda x: int(le.transform([x])[0]) if x in le.classes_ else 0
        )
    for col in numerical_columns:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(-1)
    df[numerical_columns] = scaler.transform(df[numerical_columns])
    return df


def ask_gemini(row):
    prompt = f"""
You are a cybersecurity analyst reviewing flagged IoT network traffic.
An XGBoost model classified this flow as malicious with {row['confidence']*100:.1f}% confidence.

Flow details:
- proto: {row['proto']}, service: {row['service']}, conn_state: {row['conn_state']}
- orig_bytes: {row['orig_bytes']:.0f}, resp_bytes: {row['resp_bytes']:.0f}
- duration: {row['duration']:.4f}s, orig_pkts: {row['orig_pkts']:.0f}, resp_pkts: {row['resp_pkts']:.0f}
- missed_bytes: {row['missed_bytes']:.0f}

Respond ONLY with a JSON object using this exact structure, no extra text:
{{
  "attack_type": "short name of the most likely attack",
  "severity": <1-5 integer rating>,
  "summary": "1-2 sentence technical summary of what happened",
  "key_indicators": ["indicator 1", "indicator 2"],
  "impact": "brief description of potential damage",
  "affected_devices": ["device type 1", "device type 2"],
  "mitigations": ["action 1", "action 2", "action 3"],
  "log_signatures": ["pattern to look for 1", "pattern 2"]
}}
"""
    raw = client.models.generate_content(model="gemini-2.5-flash", contents=prompt).text
    cleaned = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    return json.loads(cleaned)


@app.get("/")
def health():
    return {"status": "ok"}


# runs xgboost on uploaded file and streams progress back
@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    contents = await file.read()
    filename = file.filename

    async def generate():
        try:
            print("[1/3] Reading file...")
            yield event({"type": "step", "message": "Reading file..."})

            if filename.endswith(".parquet"):
                df_raw = pd.read_parquet(BytesIO(contents))
            elif filename.endswith(".csv"):
                df_raw = pd.read_csv(BytesIO(contents))
            else:
                yield event({"type": "error", "message": "Only .csv and .parquet files are supported"})
                return

            missing = [c for c in categorical_columns + numerical_columns if c not in df_raw.columns]
            if missing:
                yield event({"type": "error", "message": f"Missing required columns: {missing}"})
                return

            print(f"[1/3] Done — {len(df_raw):,} flows loaded")
            yield event({"type": "step", "message": f"File parsed · {len(df_raw):,} flows loaded"})
            print("[2/3] Running XGBoost model...")
            yield event({"type": "step", "message": "Running XGBoost model..."})

            # keep a copy before scaling since gemini needs the real numbers
            df_original = df_raw[categorical_columns + numerical_columns].copy()
            for col in categorical_columns:
                df_original[col] = df_original[col].fillna("Unknown").astype(str)
            for col in numerical_columns:
                df_original[col] = pd.to_numeric(df_original[col], errors="coerce").fillna(-1)

            df_model = preprocess(df_raw)
            dmatrix = xgb.DMatrix(df_model)
            probs = model.predict(dmatrix)

            df_original["confidence"] = probs
            df_original["predicted"] = (probs > 0.5).astype(int)
            malicious = df_original[df_original["predicted"] == 1].sort_values("confidence", ascending=False).copy()
            malicious["flow_id"] = range(1, len(malicious) + 1)

            # run rule-based classifier on all flagged flows
            malicious["attack_type"], malicious["severity"] = classify_all(malicious)

            # store so /threats can paginate later
            global _malicious_df
            _malicious_df = malicious.copy()

            print(f"[2/3] Done — {len(malicious):,} malicious flows detected")
            yield event({"type": "step", "message": f"Model complete · {len(malicious):,} malicious flows detected"})

            if malicious.empty:
                yield event({"type": "result", "threats": [], "total_flows": len(df_raw), "malicious_count": 0})
                return

            # grab top 15 per severity so every filter tab has something to show
            diverse = (
                malicious
                .sort_values("confidence", ascending=False)
                .groupby("severity", observed=True)
                .head(15)
                .reset_index(drop=True)
            )

            threats = []
            for _, row in diverse.iterrows():
                threats.append({
                    "proto": row["proto"],
                    "service": row["service"],
                    "conn_state": row["conn_state"],
                    "confidence": float(row["confidence"]),
                    "attack_type": row["attack_type"],
                    "severity": int(row["severity"]),
                    "orig_bytes": float(row["orig_bytes"]),
                    "resp_bytes": float(row["resp_bytes"]),
                    "duration": float(row["duration"]),
                    "orig_pkts": float(row["orig_pkts"]),
                    "resp_pkts": float(row["resp_pkts"]),
                    "missed_bytes": float(row["missed_bytes"]),
                })

            avg_confidence = float(malicious["confidence"].mean())

            # aggregate stats across all malicious flows for analytics
            conf = malicious["confidence"]
            aggregates = {
                "proto": malicious["proto"].value_counts().to_dict(),
                "service": malicious["service"].value_counts().head(10).to_dict(),
                "conn_state": malicious["conn_state"].value_counts().head(10).to_dict(),
                "attack_type_dist": {k: int(v) for k, v in malicious["attack_type"].value_counts().to_dict().items()},
                "severity_dist": {
                    "Critical (5)": int((malicious["severity"] == 5).sum()),
                    "High (4)": int((malicious["severity"] == 4).sum()),
                    "Medium (3)": int((malicious["severity"] == 3).sum()),
                    "Low (≤2)": int((malicious["severity"] <= 2).sum()),
                },
                "confidence_dist": {
                    "50-70%": int(((conf >= 0.50) & (conf < 0.70)).sum()),
                    "70-80%": int(((conf >= 0.70) & (conf < 0.80)).sum()),
                    "80-90%": int(((conf >= 0.80) & (conf < 0.90)).sum()),
                    "90-95%": int(((conf >= 0.90) & (conf < 0.95)).sum()),
                    "95-99%": int(((conf >= 0.95) & (conf < 0.99)).sum()),
                    "99%+": int((conf >= 0.99).sum()),
                },
            }

            yield event({
                "type": "result",
                "threats": threats,
                "total_flows": len(df_raw),
                "malicious_count": int(len(malicious)),
                "avg_confidence": round(avg_confidence * 100, 1),
                "aggregates": aggregates,
            })

        except Exception as e:
            print(f"[ERROR] {e}")
            yield event({"type": "error", "message": str(e)})

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# called when user clicks "query ai agent" on a threat
class ThreatData(BaseModel):
    proto: str
    service: str
    conn_state: str
    confidence: float
    orig_bytes: float = -1
    resp_bytes: float = -1
    duration: float = -1
    orig_pkts: float = -1
    resp_pkts: float = -1
    missed_bytes: float = -1


@app.get("/threats")
def get_threats(
    page: int = 0,
    page_size: int = 15,
    severity: str = "ALL",
    attack_type: str = "ALL",
    sort_dir: str = "desc",
):
    if _malicious_df is None:
        return {"items": [], "total": 0, "page": 0, "total_pages": 0, "attack_types": []}

    df = _malicious_df.copy()

    # filter by severity
    if severity == "CRITICAL":
        df = df[df["severity"] == 5]
    elif severity == "HIGH":
        df = df[df["severity"] == 4]
    elif severity == "MEDIUM":
        df = df[df["severity"] == 3]
    elif severity == "LOW":
        df = df[df["severity"] <= 2]

    # get attack types for the current severity before filtering further
    attack_types = sorted(df["attack_type"].unique().tolist())

    # filter by attack type
    if attack_type != "ALL":
        df = df[df["attack_type"] == attack_type]

    df = df.sort_values("confidence", ascending=(sort_dir == "asc"))

    total = len(df)
    total_pages = max(1, (total + page_size - 1) // page_size)
    page = min(page, total_pages - 1)

    cols = ["flow_id", "proto", "service", "conn_state", "confidence", "attack_type", "severity",
            "orig_bytes", "resp_bytes", "duration", "orig_pkts", "resp_pkts", "missed_bytes"]
    items = df.iloc[page * page_size: (page + 1) * page_size][cols].to_dict("records")

    return {"items": items, "total": total, "page": page, "total_pages": total_pages, "attack_types": attack_types}


@app.post("/explain")
def explain(threat: ThreatData):
    print(f"[explain] querying gemini for {threat.proto}/{threat.service}/{threat.conn_state}...")
    # run classifier first so gemini can't override the severity
    _, hardcoded_severity = classify_all(
        pd.DataFrame([{"proto": threat.proto, "service": threat.service, "conn_state": threat.conn_state}])
    )
    analysis = ask_gemini(threat.model_dump())
    analysis["severity"] = int(hardcoded_severity.iloc[0])
    print(f"[explain] done — {analysis.get('attack_type', '?')} severity={analysis['severity']}")
    return analysis
