"""Full pipeline smoke test — SpiderForge v3."""

import asyncio
import sys

from spiderforge.core.engine import AssessmentEngine


async def main() -> int:
    # غيّر ده لأي هدف تحب
    target = "http://demo.testfire.net/"

    def on_event(name: str, data: dict) -> None:
        if name == "scan_started":
            print(f"[*] Scan started: {data.get('target')}")
        elif name == "recon_started":
            print(f"[*] Recon started...")
        elif name == "tech_detected":
            print(f"    [tech] {data.get('name')} {data.get('version', '')}")
        elif name == "crawl_started":
            print(f"[*] Crawling...")
        elif name == "crawl_completed":
            print(f"    [crawl] pages={data.get('pages')} | "
                  f"endpoints={data.get('endpoints')} | "
                  f"forms={data.get('forms')} | "
                  f"duration={data.get('duration', 0):.1f}s")
        elif name == "scanners_started":
            print(f"[*] Running scanners on {data.get('endpoints_count')} URLs...")
        elif name == "finding_created":
            print(f"    [{data.get('severity'):6s}] {data.get('title')}")
        elif name in ("error", "recon_error"):
            print(f"    [ERROR] {data}")

    engine = AssessmentEngine(
        target_url=target,
        max_urls=30,
        max_depth=2,
        max_concurrency=5,
        rate_limit_rps=5.0,
        on_event=on_event,
    )

    result = await engine.run()

    print("\n" + "=" * 70)
    print(f"Target:             {result.target}")
    print(f"Duration:           {(result.end_time - result.start_time).total_seconds():.1f}s")
    print(f"Discovered URLs:    {len(result.discovered_urls)}")
    print(f"Technologies:       {len(result.technologies)}")
    print(f"Findings:           {len(result.findings)}")
    print(f"Summary:            {result.summary}")
    print("=" * 70)

    if result.findings:
        print("\nFindings (top 15):")
        for f in result.findings[:15]:
            print(f"  [{f.severity.value:6s}] {f.title}")
            print(f"           URL: {f.url}")
            if f.parameter:
                print(f"           Param: {f.parameter}")

    return 0 if result.findings else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))