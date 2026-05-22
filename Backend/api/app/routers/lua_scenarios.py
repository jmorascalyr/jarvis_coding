"""Lua scenario management API"""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path as FastAPIPath
from pydantic import BaseModel, Field

from app.core.simple_auth import require_read_access, require_write_access
from app.models.responses import BaseResponse

router = APIRouter()

LUA_BASE_DIR = Path(__file__).resolve().parents[3] / "scenarios" / "lua"
USER_LUA_DIR = LUA_BASE_DIR / "user"
METADATA_FILE = USER_LUA_DIR / "_metadata.json"
SCENARIO_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]{2,63}$")

OOTB_SCENARIOS = [
    {
        "id": "identity_theft_ransomware_lua",
        "name": "Cross-Platform Identity Theft & Ransomware (Lua)",
        "description": (
            "Portable Lua version of the identity-led ransomware scenario using the unified Lua sender API."
        ),
        "path": LUA_BASE_DIR / "identity_theft_ransomware.lua",
    }
]


class LuaScenarioCreate(BaseModel):
    scenario_id: str = Field(..., alias="id", description="Unique scenario identifier")
    name: str = Field(..., min_length=3, max_length=120)
    description: str = Field(..., min_length=3, max_length=2000)
    source: str = Field(..., min_length=1, description="Lua source code")


class LuaScenarioUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=3, max_length=120)
    description: Optional[str] = Field(None, min_length=3, max_length=2000)
    source: Optional[str] = Field(None, min_length=1)


def _ensure_user_dir() -> None:
    USER_LUA_DIR.mkdir(parents=True, exist_ok=True)


def _load_metadata() -> Dict[str, Dict[str, Any]]:
    _ensure_user_dir()
    if METADATA_FILE.exists():
        try:
            return json.loads(METADATA_FILE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
    return {}


def _save_metadata(metadata: Dict[str, Dict[str, Any]]) -> None:
    _ensure_user_dir()
    METADATA_FILE.write_text(json.dumps(metadata, indent=2), encoding="utf-8")


def _user_scenario_path(scenario_id: str) -> Path:
    return USER_LUA_DIR / f"{scenario_id}.lua"


def _validate_scenario_id(scenario_id: str) -> None:
    if not SCENARIO_ID_PATTERN.match(scenario_id):
        raise HTTPException(
            status_code=422,
            detail=(
                "Scenario id must be 3-64 characters, start with a letter, and contain only lowercase letters, numbers, or underscores."
            ),
        )


def _serialize_entry(entry: Dict[str, Any], category: str) -> Dict[str, Any]:
    path = entry.get("path")
    stat_data = None
    if path and Path(path).exists():
        stat = Path(path).stat()
        stat_data = {
            "size_bytes": stat.st_size,
            "updated_at": datetime.utcfromtimestamp(stat.st_mtime).isoformat() + "Z",
        }

    serialized = {
        "id": entry["id"],
        "name": entry.get("name", entry["id"]),
        "description": entry.get("description", ""),
        "category": category,
        "engine": "lua",
        "path": str(path) if path else None,
        "user_editable": category == "user",
    }
    if stat_data:
        serialized.update(stat_data)
    return serialized


def _list_ootb_scenarios() -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for entry in OOTB_SCENARIOS:
        if not Path(entry["path"]).exists():
            continue
        results.append(_serialize_entry(entry, category="ootb"))
    return results


def _list_user_scenarios() -> List[Dict[str, Any]]:
    metadata = _load_metadata()
    scenarios: List[Dict[str, Any]] = []
    for scenario_id, meta in metadata.items():
        path = _user_scenario_path(scenario_id)
        if not path.exists():
            continue
        entry = {
            "id": scenario_id,
            "name": meta.get("name", scenario_id),
            "description": meta.get("description", ""),
            "path": path,
        }
        serialized = _serialize_entry(entry, category="user")
        serialized["created_at"] = meta.get("created_at")
        serialized["updated_at"] = meta.get("updated_at") or serialized.get("updated_at")
        scenarios.append(serialized)
    # Sort alphabetically by name
    scenarios.sort(key=lambda item: item["name"].lower())
    return scenarios


def _load_scenario_source(path: Path) -> str:
    if not path.exists():
        raise HTTPException(status_code=404, detail="Scenario file not found")
    return path.read_text(encoding="utf-8")


def _resolve_scenario(scenario_id: str) -> Dict[str, Any]:
    for entry in OOTB_SCENARIOS:
        if entry["id"] == scenario_id:
            return {"entry": entry, "category": "ootb", "path": Path(entry["path"]) }
    metadata = _load_metadata()
    if scenario_id in metadata:
        path = _user_scenario_path(scenario_id)
        if not path.exists():
            raise HTTPException(status_code=404, detail="Scenario file missing")
        entry = {
            "id": scenario_id,
            "name": metadata[scenario_id].get("name", scenario_id),
            "description": metadata[scenario_id].get("description", ""),
            "path": path,
        }
        return {"entry": entry, "category": "user", "path": path, "meta": metadata[scenario_id]}
    raise HTTPException(status_code=404, detail="Scenario not found")


@router.get("", response_model=BaseResponse)
async def list_lua_scenarios(_: str = Depends(require_read_access)):
    data = {
        "ootb": _list_ootb_scenarios(),
        "user": _list_user_scenarios(),
    }
    return BaseResponse(success=True, data=data)


@router.get("/{scenario_id}", response_model=BaseResponse)
async def get_lua_scenario(
    scenario_id: str = FastAPIPath(..., description="Scenario identifier"),
    _: str = Depends(require_read_access),
):
    resolved = _resolve_scenario(scenario_id)
    scenario = _serialize_entry(resolved["entry"], resolved["category"])
    scenario["source"] = _load_scenario_source(Path(resolved["path"]))
    return BaseResponse(success=True, data={"scenario": scenario})


@router.post("", response_model=BaseResponse)
async def create_lua_scenario(
    payload: LuaScenarioCreate,
    _: str = Depends(require_write_access),
):
    scenario_id = payload.scenario_id.strip()
    _validate_scenario_id(scenario_id)

    if any(entry["id"] == scenario_id for entry in OOTB_SCENARIOS):
        raise HTTPException(status_code=409, detail="Scenario id is reserved")

    metadata = _load_metadata()
    if scenario_id in metadata or _user_scenario_path(scenario_id).exists():
        raise HTTPException(status_code=409, detail="Scenario id already exists")

    path = _user_scenario_path(scenario_id)
    path.write_text(payload.source, encoding="utf-8")

    timestamp = datetime.utcnow().isoformat() + "Z"
    metadata[scenario_id] = {
        "name": payload.name,
        "description": payload.description,
        "created_at": timestamp,
        "updated_at": timestamp,
    }
    _save_metadata(metadata)

    entry = {
        "id": scenario_id,
        "name": payload.name,
        "description": payload.description,
        "path": path,
    }
    scenario = _serialize_entry(entry, category="user")
    scenario["created_at"] = timestamp
    scenario["updated_at"] = timestamp

    return BaseResponse(success=True, data={"scenario": scenario})


@router.put("/{scenario_id}", response_model=BaseResponse)
async def update_lua_scenario(
    payload: LuaScenarioUpdate,
    scenario_id: str = FastAPIPath(..., description="Scenario identifier"),
    _: str = Depends(require_write_access),
):
    resolved = _resolve_scenario(scenario_id)
    if resolved["category"] != "user":
        raise HTTPException(status_code=400, detail="Only user scenarios can be edited")

    metadata = _load_metadata()
    meta = metadata.get(scenario_id, {})

    if payload.source is not None:
        _user_scenario_path(scenario_id).write_text(payload.source, encoding="utf-8")

    if payload.name is not None:
        meta["name"] = payload.name
    if payload.description is not None:
        meta["description"] = payload.description

    meta["updated_at"] = datetime.utcnow().isoformat() + "Z"
    metadata[scenario_id] = meta
    _save_metadata(metadata)

    entry = {
        "id": scenario_id,
        "name": meta.get("name", scenario_id),
        "description": meta.get("description", ""),
        "path": _user_scenario_path(scenario_id),
    }
    scenario = _serialize_entry(entry, category="user")
    scenario["created_at"] = meta.get("created_at")
    scenario["updated_at"] = meta.get("updated_at")
    scenario["source"] = _load_scenario_source(entry["path"])

    return BaseResponse(success=True, data={"scenario": scenario})


@router.delete("/{scenario_id}", response_model=BaseResponse)
async def delete_lua_scenario(
    scenario_id: str = FastAPIPath(..., description="Scenario identifier"),
    _: str = Depends(require_write_access),
):
    resolved = _resolve_scenario(scenario_id)
    if resolved["category"] != "user":
        raise HTTPException(status_code=400, detail="Cannot delete built-in scenarios")

    path = _user_scenario_path(scenario_id)
    if path.exists():
        path.unlink()

    metadata = _load_metadata()
    metadata.pop(scenario_id, None)
    _save_metadata(metadata)

    return BaseResponse(success=True, data={"deleted": scenario_id})
