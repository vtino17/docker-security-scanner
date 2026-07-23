import argparse
import sys
from .scanner import scan_all_containers, scan_container, check_image_age
from .reporter import generate_report


def main():
    parser = argparse.ArgumentParser(
        description="Docker Security Scanner - scan containers for security issues")
    parser.add_argument("container", nargs="?", help="Container ID or name (default: all running)")
    parser.add_argument("--image", help="Check image age")
    parser.add_argument("--output", "-o", help="Write HTML report to file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show PASS findings too")
    args = parser.parse_args()

    results = []

    if args.image:
        finding = check_image_age(args.image)
        if finding:
            results.append(type("res", (), {"container_id": "N/A", "image": args.image,
                "findings": [finding], "healthy": True})())
    elif args.container:
        r = scan_container(args.container)
        results.append(r)
    else:
        results = scan_all_containers()

    if not results:
        print("No containers found.")
        return

    total = 0
    for scan in results:
        level = "HEALTHY" if scan.healthy else "ISSUES FOUND"
        print(f"\n=== {scan.container_id} ({scan.image}) [{level}] ===")
        for f in scan.findings:
            if f.severity == "PASS" and not args.verbose:
                continue
            total += 1
            flag = {"CRITICAL": "!!", "HIGH": "! ", "MEDIUM": "~ ", "LOW": "  ", "PASS": "OK", "INFO": "->"}.get(
                f.severity, "  ")
            print(f"  [{f.severity:8}] {flag} {f.check}: {f.status}")
            if args.verbose:
                print(f"          {f.detail}")

    print(f"\nTotal findings: {total}")

    if args.output:
        html = generate_report(results)
        with open(args.output, "w") as f:
            f.write(html)
        print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
