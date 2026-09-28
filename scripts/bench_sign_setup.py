#!/usr/bin/env python3
"""对比指定 main 提交与当前工作区的 sign 延迟，使用独立构建目录。"""
import argparse
import csv
import io
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import tarfile
import tempfile


def build(source, target):
    command = ["cargo", "test", "--manifest-path", str(source / "Cargo.toml"),
               "--target-dir", str(target), "--release", "--locked", "--offline",
               "--no-run", "--message-format=json"]
    result = subprocess.run(command, check=True, text=True, stdout=subprocess.PIPE)
    artifacts = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    return next(item["executable"] for item in artifacts
                if item.get("reason") == "compiler-artifact" and item.get("executable")
                and item["target"]["name"] == "svarog_ecdsa_otmta")


def measure(executables, output, samples=5, blocks=4, warmup=3):
    output.mkdir(parents=True, exist_ok=True)
    rows, keygen = [], []
    for block in range(blocks):
        order = ["baseline", "inline"] if block % 2 == 0 else ["inline", "baseline"]
        for variant in order:
            env = dict(os.environ, OT_BENCH_LABEL=f"{variant}-{block}",
                       OT_BENCH_SAMPLES=str(samples), OT_BENCH_WARMUP=str(warmup),
                       OT_BENCH_EXPECT_EMPTY="1" if variant == "inline" else "0")
            result = subprocess.run([executables[variant], "timing_bench::sign_latency",
                                     "--exact", "--ignored", "--nocapture"],
                                    env=env, check=True, text=True, stdout=subprocess.PIPE,
                                    timeout=600)
            (output / f"{variant}-{block}.log").write_text(result.stdout)
            for line in result.stdout.splitlines():
                fields = line.split(",")
                if fields[0] == "TIMING":
                    _, _, case, batch, index, ms, rounds = fields
                    rows.append([variant, block, case, int(batch), int(index), float(ms), int(rounds)])
                elif fields[0] == "KEYGEN":
                    _, _, case, ms, rounds = fields
                    keygen.append([variant, block, case, float(ms), int(rounds)])
            print(f"Completed {variant} block {block + 1}/{blocks}", flush=True)
    with (output / "raw.csv").open("w", newline="") as f:
        writer = csv.writer(f, lineterminator="\n")
        writer.writerow(["variant", "block", "case", "batch", "sample", "ms", "rounds"])
        writer.writerows(rows)
    with (output / "keygen.csv").open("w", newline="") as f:
        writer = csv.writer(f, lineterminator="\n")
        writer.writerow(["variant", "block", "case", "ms", "rounds"])
        writer.writerows(keygen)
    summary = []
    for case in ["2-of-2", "2-of-3", "3-of-3"]:
        for batch in [1, 4]:
            for variant in ["baseline", "inline"]:
                selected = [row for row in rows if row[0] == variant and row[2] == case and row[3] == batch]
                values = sorted(row[5] for row in selected)
                assert len(values) == samples * blocks
                assert len({row[6] for row in selected}) == 1
                summary.append(dict(variant=variant, case=case, batch=batch, samples=len(values),
                                    median_ms=statistics.median(values), mean_ms=statistics.mean(values),
                                    p95_ms=values[max(0, (95 * len(values) + 99) // 100 - 1)],
                                    rounds=selected[0][6]))
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    metadata = dict(platform=platform.platform(), cpu_count=os.cpu_count(),
                    affinity=sorted(os.sched_getaffinity(0)), runtime_workers=8,
                    samples_per_block=samples, blocks=blocks, warmup_per_block=warmup,
                    rustc=subprocess.check_output(["rustc", "--version"], text=True).strip())
    for line in Path("/proc/cpuinfo").read_text().splitlines():
        if line.startswith("model name"):
            metadata["cpu"] = line.split(":", 1)[1].strip()
            break
    (output / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", default="main")
    parser.add_argument("--output", type=Path, default=Path("benchmarks/sign-setup"))
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    baseline_commit = subprocess.check_output(["git", "-C", str(repo), "rev-parse", args.baseline], text=True).strip()
    with tempfile.TemporaryDirectory(prefix="sign-setup-bench-") as tmp:
        tmp = Path(tmp)
        baseline = tmp / "baseline"
        archive = subprocess.check_output(["git", "-C", str(repo), "archive", baseline_commit])
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(baseline, filter="data")
        shutil.copyfile(repo / "src/timing_bench.rs", baseline / "src/timing_bench.rs")
        lib = baseline / "src/lib.rs"
        if "mod timing_bench;" not in lib.read_text():
            lib.write_text(lib.read_text() + "\n#[cfg(test)]\nmod timing_bench;\n")
        cargo = baseline / "Cargo.toml"
        cargo.write_text(cargo.read_text().replace('"macros", "time"', '"macros", "time", "sync"'))
        executables = {"baseline": build(baseline, tmp / "baseline-target"),
                       "inline": build(repo, tmp / "inline-target")}
        measure(executables, args.output)
        (args.output / "baseline.txt").write_text(baseline_commit + "\n")


if __name__ == "__main__":
    main()
