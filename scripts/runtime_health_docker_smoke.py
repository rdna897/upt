#!/usr/bin/env python3
"""Read-only Docker CLI compatibility smoke for the runtime health collector."""

from collections import Counter

from docker_update_manager.runtime import RuntimeProbeError, collect_runtime_containers


def main() -> int:
    try:
        containers = collect_runtime_containers()
    except RuntimeProbeError as exc:
        exit_code = exc.exit_code if exc.exit_code is not None else "none"
        print(
            "Runtime Docker CLI smoke failed "
            f"stage={exc.stage} category={exc.category} "
            f"failure_class={exc.failure_class} exit_code={exit_code}"
        )
        return 1
    except Exception as exc:
        failure_class = "".join(char for char in type(exc).__name__ if char.isalnum() or char == "_")[:64]
        print(f"Runtime Docker CLI smoke failed stage=collect category=probe_failed failure_class={failure_class or 'UnknownError'}")
        return 1

    if not containers:
        print("Runtime Docker CLI smoke inconclusive: no containers were available to inspect.")
        return 2

    health_counts = Counter(item.get("healthcheck", "unknown") for item in containers)
    no_healthcheck = health_counts.get("none", 0)
    healthchecked = len(containers) - no_healthcheck
    if not no_healthcheck:
        print("Runtime Docker CLI smoke inconclusive: inventory has no container without a healthcheck.")
        return 2
    if not healthchecked:
        print("Runtime Docker CLI smoke inconclusive: inventory has no healthchecked container.")
        return 2
    unsupported = sorted(set(health_counts) - {"none", "healthy", "unhealthy", "starting"})
    if unsupported:
        print("Runtime Docker CLI smoke failed: healthcheck status was not recognised.")
        return 1

    states = ",".join(f"{name}:{health_counts[name]}" for name in sorted(health_counts))
    print(
        "Runtime Docker CLI smoke passed "
        f"containers={len(containers)} no_healthcheck={no_healthcheck} "
        f"healthchecked={healthchecked} health_states={states}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
