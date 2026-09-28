"""Motor de fusion y scoring multi-motor (Capa 3).

Combina veredictos de los 6 motores con pesos ponderados adaptativos.
Umbrales configurables: <40 deliver, 40-69 quarantena, >=70 block.
"""
import json
import sqlite3
import time

from app import config
from app.mail import engines

SCORE_CLEAN = 0


def fused_score(engine_results: dict, use_adaptive: bool = True) -> dict:
    """Fusion ponderada con pesos configurables (adaptativo opcional)."""
    total_w = 0.0
    acc = 0.0
    per_engine = {}
    for name, weights in engines.ENGINE_WEIGHTS.items():
        result = engine_results.get(name)
        if not result or result.get("skip"):
            continue
        w = weights
        if use_adaptive and result.get("score", 0) > 60:
            w *= 1.3  # los motores son mas fiables en extremos
        acc += result["score"] * w
        total_w += w
        per_engine[name] = {"score": result["score"], "verdict": result["verdict"], "weight": round(w, 3)}
    composite = round(acc / total_w, 1) if total_w else 0.0

    if composite >= config.BLOCK_THRESHOLD:
        vote = "block"
    elif composite >= config.QUARANTINE_THRESHOLD:
        vote = "quarantine"
    else:
        vote = "deliver"

    # deteccion de desacuerdo entre motores
    verdicts = [p["verdict"] for p in per_engine.values()]
    disagreement = False
    if verdicts and (max(verdicts.count(v) for v in set(verdicts)) <= len(verdicts) - 1 if len(verdicts) > 1 else False):
        disagreement = True

    return {
        "composite_score": composite,
        "vote": vote,
        "engines": per_engine,
        "engines_count": len(per_engine),
        "disagreement": disagreement,
        "computed_at": time.time(),
    }


def record_verdict(msg_id: str, engine_results: dict, fused: dict) -> None:
    """Registra el veredicto en la tabla de mensajes (usado por quarantine)."""
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS veredictos (
            msg_id TEXT PRIMARY KEY,
            composite REAL,
            vote TEXT,
            engine_results TEXT
        )"""
    )
    conn.execute(
        "INSERT OR REPLACE INTO veredictos (msg_id, composite, vote, engine_results) VALUES (?,?,?,?)",
        (msg_id, fused["composite_score"], fused["vote"],
         json.dumps({k: v for k, v in engine_results.items()}, ensure_ascii=False, default=str)),
    )
    conn.commit()
    conn.close()


def get_verdict(msg_id: str):
    conn = sqlite3.connect(config.DB_PATH)
    row = conn.execute("SELECT composite, vote, engine_results FROM veredictos WHERE msg_id=?", (msg_id,)).fetchone()
    conn.close()
    if not row:
        return None
    return {"composite": row[0], "vote": row[1], "engine_results": json.loads(row[2])}


def engine_accuracy_stats() -> list:
    """Estadisticas agregadas por motor para el dashboard (efectividad de reglas)."""
    conn = sqlite3.connect(config.DB_PATH)
    rows = conn.execute(
        "SELECT vote, engine_results FROM veredictos"
    ).fetchall()
    conn.close()
    stats = {name: {"n_analisis": 0, "n_detect": 0, "sum_score": 0.0} for name in engines.ENGINE_WEIGHTS}
    for vote, er_json in rows:
        try:
            er = json.loads(er_json)
        except Exception:
            continue
        for name, r in er.items():
            if name not in stats or not isinstance(r, dict):
                continue
            stats[name]["n_analisis"] += 1
            stats[name]["sum_score"] += r.get("score", 0)
            if r.get("score", 0) >= config.QUARANTINE_THRESHOLD:
                stats[name]["n_detect"] += 1
    result = []
    for name, s in stats.items():
        result.append({
            "motor": name,
            "n_analisis": s["n_analisis"],
            "n_detect": s["n_detect"],
            "tasa_deteccion": round(s["n_detect"] / s["n_analisis"] * 100, 1) if s["n_analisis"] else 0.0,
            "puntuacion_media": round(s["sum_score"] / s["n_analisis"], 1) if s["n_analisis"] else 0.0,
        })
    return result