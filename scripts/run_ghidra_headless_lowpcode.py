#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


DEFAULT_PROJECT_ROOT = Path("/Volumes/DO/00_gitProject/01_tdo/ghidra_project_TDO")
DEFAULT_OUTPUT_ROOT = Path("/Volumes/DO/00_gitProject/01_tdo/lowpcode_data_origin/samples/low_pcode")
SCRIPT_NAME = "lowpcode_json_dumper.py"


def find_analyze_headless(explicit: str | None) -> Path:
    if explicit:
        candidate = Path(explicit).expanduser()
        if candidate.is_file():
            return candidate
        raise SystemExit(f"analyzeHeadless not found: {candidate}")

    env_path = os.environ.get("GHIDRA_HEADLESS")
    if env_path:
        candidate = Path(env_path).expanduser()
        if candidate.is_file():
            return candidate

    install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if install_dir:
        candidate = Path(install_dir).expanduser() / "support" / "analyzeHeadless"
        if candidate.is_file():
            return candidate

    for root in (Path("/Applications"), Path("/opt")):
        try:
            matches = sorted(root.rglob("analyzeHeadless"))
        except (OSError, PermissionError):
            continue
        for candidate in matches:
            if candidate.is_file():
                return candidate

    raise SystemExit(
        "analyzeHeadless not found. Set GHIDRA_HEADLESS or GHIDRA_INSTALL_DIR, "
        "or pass --analyze-headless."
    )


def find_projects(project_root: Path, project_names: list[str]) -> list[Path]:
    if project_names:
        projects = []
        for name in project_names:
            candidate = project_root / f"{name}.gpr"
            if not candidate.is_file():
                candidate = Path(name).expanduser()
            if not candidate.is_file() or candidate.suffix != ".gpr":
                raise SystemExit(f"Ghidra project .gpr not found: {name}")
            projects.append(candidate)
        return projects
    return sorted(project_root.rglob("*.gpr"))


def build_command(
    analyze_headless: Path,
    project_file: Path,
    output_root: Path,
    script_dir: Path,
    program: str | None,
    root_prefix: str,
    max_depth: int,
    extra_script_args: list[str],
) -> list[str]:
    project_location = project_file.parent
    project_name = project_file.stem
    command = [
        str(analyze_headless),
        str(project_location),
        project_name,
        "-process",
    ]
    if program:
        command.append(Path(program).name)
    command.extend(
        [
            "-recursive",
            "-readOnly",
            "-scriptPath",
            str(script_dir),
            "-postScript",
            SCRIPT_NAME,
            "--output-root",
            str(output_root),
            "--root-prefix",
            root_prefix,
            "--max-depth",
            str(max_depth),
        ]
    )
    command.extend(extra_script_args)
    return command


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Ghidra headless low-pcode extraction for every .gpr project under a root."
    )
    parser.add_argument("--project-root", default=str(DEFAULT_PROJECT_ROOT))
    parser.add_argument("--output-root", default=str(DEFAULT_OUTPUT_ROOT))
    parser.add_argument("--analyze-headless")
    parser.add_argument("--project", action="append", default=[], help="Project name or .gpr path. Repeatable.")
    parser.add_argument("--program", help="Optional Ghidra project program path/name to pass to -process.")
    parser.add_argument("--root-prefix", default="case_DFB")
    parser.add_argument("--max-depth", type=int, default=8)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("script_args", nargs=argparse.REMAINDER, help="Extra args passed to lowpcode_json_dumper.py")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    script_dir = repo_root / "scripts"
    output_root = Path(args.output_root).expanduser().resolve()
    project_root = Path(args.project_root).expanduser().resolve()
    analyze_headless = find_analyze_headless(args.analyze_headless)
    projects = find_projects(project_root, args.project)
    extra_script_args = list(args.script_args)
    if extra_script_args and extra_script_args[0] == "--":
        extra_script_args = extra_script_args[1:]

    if not projects:
        raise SystemExit(f"No .gpr projects found under {project_root}")

    print(f"[*] analyzeHeadless: {analyze_headless}")
    print(f"[*] project count: {len(projects)}")
    print(f"[*] output root: {output_root}")
    output_root.mkdir(parents=True, exist_ok=True)

    for project_file in projects:
        command = build_command(
            analyze_headless=analyze_headless,
            project_file=project_file,
            output_root=output_root,
            script_dir=script_dir,
            program=args.program,
            root_prefix=args.root_prefix,
            max_depth=args.max_depth,
            extra_script_args=extra_script_args,
        )
        print("[*] running:", " ".join(command))
        if args.dry_run:
            continue
        subprocess.run(command, check=True)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as exc:
        print(f"[-] Ghidra headless failed with exit code {exc.returncode}", file=sys.stderr)
        raise SystemExit(exc.returncode)
