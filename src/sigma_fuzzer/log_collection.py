"""Collect Sysmon process events and export matching EVTX evidence."""

from __future__ import annotations

import base64
import html
import json
import ntpath
import re
import subprocess
import time
from pathlib import Path

from .models import SYSMON_EVENT_ID, SYSMON_LOG_NAME, SysmonProcessEvent, TargetCase
from .utils import int_or_none, runner_parent_matches


CLIXML_ERROR_RE = re.compile(r'<S S="Error">(.*?)</S>', re.DOTALL)
POWERSHELL_ESCAPE_RE = re.compile(r"_x([0-9A-Fa-f]{4})_")


def decode_powershell_escapes(value: str) -> str:
    """Decode PowerShell CLIXML character escapes in a text fragment."""
    return POWERSHELL_ESCAPE_RE.sub(lambda match: chr(int(match.group(1), 16)), value)


def clean_powershell_error(value: str) -> str:
    """Return a compact human-readable PowerShell error message."""
    raw = (value or "").strip()
    if not raw:
        return ""

    matches = CLIXML_ERROR_RE.findall(raw)
    text = "\n".join(matches) if matches else raw
    text = decode_powershell_escapes(html.unescape(text))
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for line in lines:
        if ": " in line and not line.startswith("+") and not line.lower().startswith("at line"):
            message = line.rsplit(": ", 1)[-1].strip()
            if message and not message.startswith("$"):
                return message
    for line in lines:
        lowered = line.lower()
        if line.startswith(("$", "+", "}")):
            continue
        if lowered.startswith(("try", "if ", "else", "at line", "categoryinfo", "fullyqualifiederrorid")):
            continue
        return line
    return lines[-1] if lines else raw


def run_powershell(script: str, timeout_seconds: int) -> tuple[int, str, str]:
    """Run a PowerShell script through an encoded command."""
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    cmd = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds, check=False)
    return result.returncode, result.stdout or "", result.stderr or ""


def latest_sysmon_record_id(timeout_seconds: int) -> tuple[int | None, str]:
    """Read the latest Sysmon RecordID from the operational log."""
    script = f"""
$ErrorActionPreference = 'Stop'
try {{
  $event = Get-WinEvent -LogName '{SYSMON_LOG_NAME}' -MaxEvents 1 -ErrorAction Stop
  if ($null -eq $event) {{
    '0'
  }} else {{
    [string]$event.RecordId
  }}
}} catch {{
  Write-Error $_.Exception.Message
  exit 1
}}
"""
    try:
        code, stdout, stderr = run_powershell(script, timeout_seconds)
    except subprocess.TimeoutExpired:
        return None, f"timed out reading latest RecordID after {timeout_seconds}s"
    if code != 0:
        return None, clean_powershell_error(stderr or stdout or f"PowerShell exit code {code}")
    text = stdout.strip().splitlines()[-1] if stdout.strip() else ""
    try:
        return int(text), ""
    except ValueError:
        return None, f"failed to parse latest RecordID from PowerShell output: {text!r}"


def eventlog_recordid_query(start_record_id: int, end_record_id: int) -> str:
    """Build an XPath query for Sysmon Event ID 1 over a RecordID range."""
    return (
        f"*[System[(EventID={SYSMON_EVENT_ID}) and "
        f"(EventRecordID>{start_record_id}) and (EventRecordID<={end_record_id})]]"
    )


def process_create_events_since_query(start_record_id: int) -> str:
    """Build an XPath query for process-create events after a RecordID."""
    return f"*[System[(EventID={SYSMON_EVENT_ID}) and (EventRecordID>{start_record_id})]]"


def eventlog_process_tree_query(
    start_record_id: int,
    end_record_id: int | None,
    process_guids: set[str] | list[str],
) -> str:
    """Build an XPath query that exports events for a process tree."""
    guid_terms: list[str] = []
    for guid in sorted({item for item in process_guids if item}):
        guid_terms.append(f"Data[@Name='ProcessGuid']='{guid}'")
        guid_terms.append(f"Data[@Name='ParentProcessGuid']='{guid}'")
    guid_query = " or ".join(guid_terms) or "false()"
    record_query = f"(EventRecordID>{start_record_id})"
    if end_record_id is not None:
        record_query = f"{record_query} and (EventRecordID<={end_record_id})"
    return f"*[System[{record_query}] and EventData[({guid_query})]]"


def process_event_from_dict(item: dict[str, object]) -> SysmonProcessEvent:
    """Convert a PowerShell JSON row into a SysmonProcessEvent."""
    return SysmonProcessEvent(
        event_record_id=int_or_none(item.get("EventRecordID")) or 0,
        time_created=str(item.get("TimeCreated") or ""),
        process_guid=str(item.get("ProcessGuid") or ""),
        parent_process_guid=str(item.get("ParentProcessGuid") or ""),
        process_id=int_or_none(item.get("ProcessId")),
        parent_process_id=int_or_none(item.get("ParentProcessId")),
        commandline=str(item.get("CommandLine") or ""),
        parent_commandline=str(item.get("ParentCommandLine") or ""),
        image=str(item.get("Image") or ""),
        parent_image=str(item.get("ParentImage") or ""),
    )


def query_process_create_events_since(
    start_record_id: int,
    timeout_seconds: int,
) -> tuple[list[SysmonProcessEvent], str]:
    """Query Sysmon process-create events after a RecordID."""
    query = process_create_events_since_query(start_record_id)
    script = f"""
$ErrorActionPreference = 'Stop'
$rows = New-Object 'System.Collections.Generic.List[object]'
$events = Get-WinEvent -LogName '{SYSMON_LOG_NAME}' -FilterXPath "{query}" -ErrorAction SilentlyContinue
foreach ($event in @($events)) {{
  $xml = [xml]$event.ToXml()
  $data = @{{}}
  foreach ($item in @($xml.Event.EventData.Data)) {{
    if ($item.Name) {{
      $data[$item.Name] = [string]$item.'#text'
    }}
  }}
  $rows.Add([pscustomobject]@{{
    EventRecordID = [int64]$event.RecordId
    TimeCreated = if ($event.TimeCreated) {{ $event.TimeCreated.ToString('o') }} else {{ '' }}
    ProcessGuid = [string]$data['ProcessGuid']
    ParentProcessGuid = [string]$data['ParentProcessGuid']
    ProcessId = [string]$data['ProcessId']
    ParentProcessId = [string]$data['ParentProcessId']
    CommandLine = [string]$data['CommandLine']
    ParentCommandLine = [string]$data['ParentCommandLine']
    Image = [string]$data['Image']
    ParentImage = [string]$data['ParentImage']
  }}) | Out-Null
}}
if ($rows.Count -eq 0) {{
  '[]'
}} else {{
  ConvertTo-Json -InputObject $rows.ToArray() -Depth 4 -Compress
}}
"""
    try:
        code, stdout, stderr = run_powershell(script, timeout_seconds)
    except subprocess.TimeoutExpired:
        return [], f"timed out reading Sysmon process-create events after {timeout_seconds}s"
    if code != 0:
        return [], clean_powershell_error(stderr or stdout or f"PowerShell exit code {code}")
    text = stdout.strip()
    if not text:
        return [], ""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return [], f"failed to parse Sysmon process-create JSON: {exc}"
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return [], "Sysmon process-create query did not return a JSON array"
    events = [process_event_from_dict(item) for item in data if isinstance(item, dict)]
    return sorted(events, key=lambda event: event.event_record_id), ""


def normalize_commandline(value: str) -> str:
    """Normalize command-line text for loose comparisons."""
    return " ".join(value.lower().split())


def shell_matches_event(event: SysmonProcessEvent, shell: str) -> bool:
    """Return whether a Sysmon event appears to be the configured shell."""
    shell_name = shell.lower()
    image_name = ntpath.basename(event.image).lower()
    commandline = normalize_commandline(event.commandline)
    return image_name == shell_name or commandline.startswith(shell_name)


def find_root_process_event(
    events: list[SysmonProcessEvent],
    case: TargetCase,
    root_pid: int | None,
) -> SysmonProcessEvent | None:
    """Find the root process event for a launched target command."""
    ordered = sorted(events, key=lambda event: event.event_record_id)
    if root_pid is not None:
        for event in ordered:
            if event.process_id == root_pid and runner_parent_matches(event.parent_commandline):
                return event
        for event in ordered:
            if event.process_id == root_pid:
                return event

    target = normalize_commandline(case.target_commandline)
    for event in ordered:
        if runner_parent_matches(event.parent_commandline) and target in normalize_commandline(event.commandline):
            return event

    for event in ordered:
        if runner_parent_matches(event.parent_commandline) and shell_matches_event(event, case.shell):
            return event
    return None


def collect_process_tree(
    start_record_id: int,
    case: TargetCase,
    root_pid: int | None,
    quiescence_seconds: float,
    max_wait_seconds: float,
    query_timeout_seconds: int,
) -> tuple[SysmonProcessEvent | None, list[SysmonProcessEvent], str]:
    """Poll Sysmon until the launched process tree is complete enough."""
    deadline = time.monotonic() + max_wait_seconds
    last_growth = time.monotonic()
    poll_interval = max(0.1, min(0.5, quiescence_seconds / 4 if quiescence_seconds > 0 else 0.1))
    root_event: SysmonProcessEvent | None = None
    known_process_guids: set[str] = set()
    tree_by_guid: dict[str, SysmonProcessEvent] = {}
    last_error = ""

    while time.monotonic() <= deadline:
        events, error = query_process_create_events_since(start_record_id, query_timeout_seconds)
        if error:
            last_error = error
            break

        if root_event is None:
            root_event = find_root_process_event(events, case, root_pid)
            if root_event and root_event.process_guid:
                known_process_guids.add(root_event.process_guid)
                tree_by_guid[root_event.process_guid] = root_event
                last_growth = time.monotonic()

        if root_event is not None:
            changed = True
            while changed:
                changed = False
                for event in events:
                    if not event.process_guid:
                        continue
                    if event.process_guid in known_process_guids:
                        tree_by_guid[event.process_guid] = event
                    if event.parent_process_guid in known_process_guids and event.process_guid not in known_process_guids:
                        known_process_guids.add(event.process_guid)
                        tree_by_guid[event.process_guid] = event
                        changed = True
                        last_growth = time.monotonic()

            if time.monotonic() - last_growth >= quiescence_seconds:
                break

        time.sleep(poll_interval)

    tree = sorted(tree_by_guid.values(), key=lambda event: event.event_record_id)
    if root_event is None and not last_error:
        last_error = "root process was not found in Sysmon Event ID 1 after start_record_id"
    return root_event, tree, last_error


def export_evtx_by_record_id(
    output_path: Path,
    start_record_id: int,
    end_record_id: int,
    timeout_seconds: int,
) -> tuple[bool, str]:
    """Export Sysmon process-create events in a RecordID range to EVTX."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        output_path.unlink()
    query = eventlog_recordid_query(start_record_id, end_record_id)
    cmd = ["wevtutil.exe", "epl", SYSMON_LOG_NAME, str(output_path), f"/q:{query}", "/ow:true"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds, check=False)
    except subprocess.TimeoutExpired:
        return False, f"wevtutil timed out after {timeout_seconds}s"
    if result.returncode != 0:
        return False, (result.stderr or result.stdout or f"wevtutil exit code {result.returncode}").strip()
    if not output_path.exists():
        return False, "wevtutil completed but output EVTX was not created"
    return True, ""


def export_evtx_by_process_tree(
    output_path: Path,
    start_record_id: int,
    end_record_id: int | None,
    process_guids: set[str] | list[str],
    timeout_seconds: int,
) -> tuple[bool, str]:
    """Export Sysmon events whose process GUIDs match a collected tree."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        output_path.unlink()
    if not process_guids:
        return False, "process tree is empty; no ProcessGuid values to export"
    query = eventlog_process_tree_query(start_record_id, end_record_id, process_guids)
    cmd = ["wevtutil.exe", "epl", SYSMON_LOG_NAME, str(output_path), f"/q:{query}", "/ow:true"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds, check=False)
    except subprocess.TimeoutExpired:
        return False, f"wevtutil timed out after {timeout_seconds}s"
    if result.returncode != 0:
        return False, (result.stderr or result.stdout or f"wevtutil exit code {result.returncode}").strip()
    if not output_path.exists():
        return False, "wevtutil completed but output EVTX was not created"
    return True, ""
