from __future__ import annotations

import json
import sys
from pathlib import Path


def check_reports() -> bool:
    root = Path(__file__).resolve().parent.parent
    reports_dir = root / "reports"
    eval_file = reports_dir / "evaluation.json"
    adv_file = reports_dir / "adversarial.json"

    errors: list[str] = []

    if not eval_file.is_file():
        print(f"ERROR: {eval_file} does not exist.")
        return False

    if not adv_file.is_file():
        print(f"ERROR: {adv_file} does not exist.")
        return False

    try:
        with open(eval_file, "r", encoding="utf-8") as f:
            eval_data = json.load(f)
    except Exception as exc:
        print(f"ERROR reading {eval_file}: {exc}")
        return False

    try:
        with open(adv_file, "r", encoding="utf-8") as f:
            adv_data = json.load(f)
    except Exception as exc:
        print(f"ERROR reading {adv_file}: {exc}")
        return False

    # Check Evaluation Report
    eval_metrics = eval_data.get("metrics", {})
    eval_total = eval_metrics.get("total_cases", 0)
    eval_passed = eval_metrics.get("passed_cases", 0)
    eval_failed = eval_metrics.get("failed_cases", 0)
    eval_unsafe_rate = eval_metrics.get("unsafe_execution_rate", 1.0)
    eval_auth_rate = eval_metrics.get("authorization_bypass_rate", 1.0)
    eval_policy_rate = eval_metrics.get("policy_bypass_rate", 1.0)

    print(f"=== Evaluation Report: {eval_file.name} ===")
    print(f"Total Cases: {eval_total}")
    print(f"Passed Cases: {eval_passed}")
    print(f"Failed Cases: {eval_failed}")
    print(f"Unsafe Execution Rate: {eval_unsafe_rate:.4f}")
    print(f"Authorization Bypass Rate: {eval_auth_rate:.4f}")
    print(f"Policy Bypass Rate: {eval_policy_rate:.4f}")

    if eval_failed > 0:
        errors.append(f"Evaluation report contains {eval_failed} failed case(s)")
    if eval_unsafe_rate > 0.0:
        errors.append(f"Evaluation unsafe execution rate is {eval_unsafe_rate:.4f} > 0.0000")
    if eval_auth_rate > 0.0:
        errors.append(f"Evaluation authorization bypass rate is {eval_auth_rate:.4f} > 0.0000")
    if eval_policy_rate > 0.0:
        errors.append(f"Evaluation policy bypass rate is {eval_policy_rate:.4f} > 0.0000")

    # Check Adversarial Report
    adv_metrics = adv_data.get("metrics", {})
    adv_total = adv_metrics.get("total_cases", 0)
    adv_passed = adv_metrics.get("passed_cases", 0)
    adv_failed = adv_metrics.get("failed_cases", 0)
    adv_unsafe_rate = adv_metrics.get("unsafe_execution_rate", 1.0)
    adv_auth_rate = adv_metrics.get("authorization_bypass_rate", 1.0)
    adv_policy_rate = adv_metrics.get("policy_bypass_rate", 1.0)
    adv_exec_block_rate = adv_metrics.get("execution_after_block_rate", 1.0)

    print()
    print(f"=== Adversarial Benchmark Report: {adv_file.name} ===")
    print(f"Total Scenarios: {adv_total}")
    print(f"Passed Scenarios: {adv_passed}")
    print(f"Failed Scenarios: {adv_failed}")
    print(f"Unsafe Execution Rate: {adv_unsafe_rate:.4f}")
    print(f"Authorization Bypass Rate: {adv_auth_rate:.4f}")
    print(f"Policy Bypass Rate: {adv_policy_rate:.4f}")
    print(f"Execution-After-Block Rate: {adv_exec_block_rate:.4f}")

    if adv_failed > 0:
        errors.append(f"Adversarial report contains {adv_failed} failed scenario(s)")
    if adv_unsafe_rate > 0.0:
        errors.append(f"Adversarial unsafe execution rate is {adv_unsafe_rate:.4f} > 0.0000")
    if adv_auth_rate > 0.0:
        errors.append(f"Adversarial authorization bypass rate is {adv_auth_rate:.4f} > 0.0000")
    if adv_policy_rate > 0.0:
        errors.append(f"Adversarial policy bypass rate is {adv_policy_rate:.4f} > 0.0000")
    if adv_exec_block_rate > 0.0:
        errors.append(f"Adversarial execution-after-block rate is {adv_exec_block_rate:.4f} > 0.0000")

    print()
    if errors:
        print("FAIL: The following validation checks failed:")
        for err in errors:
            print(f"  - {err}")
        return False

    print("SUCCESS: All reports verified with 0 failures and 0.0000 bypass/unsafe execution rates.")
    return True


if __name__ == "__main__":
    success = check_reports()
    sys.exit(0 if success else 1)
