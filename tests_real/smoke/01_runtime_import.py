"""Real CAI Community 0.5.10 runtime import smoke test (no mocks)."""

import importlib.metadata


def main() -> None:
    import cai
    from cai.sdk.agents import Agent, Runner

    version = importlib.metadata.version("cai-framework")
    print("CAI_MODULE =", cai.__file__)
    print("AGENT_CLASS =", Agent.__module__ + "." + Agent.__name__)
    print("RUNNER_CLASS =", Runner.__module__ + "." + Runner.__name__)
    print("CAI_FRAMEWORK_VERSION =", version)
    if version != "0.5.10":
        raise RuntimeError(f"Expected cai-framework 0.5.10, got {version}")
    print("TEST01_RUNTIME_IMPORT_PASS")


if __name__ == "__main__":
    main()
