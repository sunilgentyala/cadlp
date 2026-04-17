"""
CADLP Command-Line Interface.

Usage:
    cadlp scan  "your prompt here"
    cadlp scan  --file prompt.txt
    cadlp demo
    cadlp eval  --dataset data/sepad10k/sample.json
"""

from __future__ import annotations

import json
import sys
import textwrap
import time
from pathlib import Path
from typing import Optional

try:
    import click
except ImportError:
    print("ERROR: 'click' not installed. Run: pip install click")
    sys.exit(1)

from cadlp.csc.pipeline import ContextualSensitivityClassifier
from cadlp.upr.redaction import UtilityPreservingRedactor
from cadlp.policy.engine import Action, PolicyEngine


BANNER = r"""
  ____    _    ____  _     ____
 / ___|  / \  |  _ \| |   |  _ \
| |     / _ \ | | | | |   | |_) |
| |___ / ___ \| |_| | |___  __/
 \____/_/   \_\____/|_____|_|

Context-Aware DLP Proxy for LLMs  v1.0.0
"""


def _print_banner():
    click.echo(click.style(BANNER, fg="cyan"))


def _colour_action(action: Action) -> str:
    colours = {
        Action.ALLOW:      "green",
        Action.REDACT:     "yellow",
        Action.BLOCK:      "red",
        Action.QUARANTINE: "magenta",
        Action.AUDIT:      "blue",
    }
    return click.style(f"[{action.value}]", fg=colours.get(action, "white"), bold=True)


@click.group()
def cli():
    """CADLP: Context-Aware DLP Proxy for LLMs."""
    pass


@cli.command()
@click.argument("prompt_text", required=False)
@click.option("--file", "-f", "prompt_file", type=click.Path(exists=True),
              help="Read prompt from a file instead of the argument.")
@click.option("--show-redacted", "-r", is_flag=True, default=True,
              help="Print the redacted prompt.")
@click.option("--json-output", "-j", is_flag=True, default=False,
              help="Emit JSON output.")
def scan(prompt_text: Optional[str], prompt_file: Optional[str],
         show_redacted: bool, json_output: bool):
    """Scan a prompt for sensitive content and display the policy decision."""
    if prompt_file:
        prompt = Path(prompt_file).read_text(encoding="utf-8")
    elif prompt_text:
        prompt = prompt_text
    else:
        click.echo("ERROR: Provide a prompt as an argument or via --file.")
        sys.exit(1)

    t0 = time.perf_counter()
    csc     = ContextualSensitivityClassifier()
    upr     = UtilityPreservingRedactor()
    policy  = PolicyEngine()

    smap    = csc.classify(prompt)
    decision = policy.evaluate(smap)
    latency_ms = (time.perf_counter() - t0) * 1000

    if json_output:
        result = {
            "action":         decision.action.value,
            "triggered_rule": decision.triggered_rule,
            "entity_types":   smap.entity_types,
            "span_count":     len(smap.spans),
            "latency_ms":     round(latency_ms, 2),
        }
        if decision.action == Action.REDACT:
            rr = upr.redact(smap)
            result["redacted_prompt"] = rr.redacted_prompt
            result["redaction_count"] = rr.num_redactions
        click.echo(json.dumps(result, indent=2))
        return

    # Human-readable output
    _print_banner()
    click.echo(f"Decision: {_colour_action(decision.action)}  "
               f"({latency_ms:.1f} ms)")
    click.echo(f"Rule:     {decision.triggered_rule or 'none'}")
    click.echo(f"Reasons:  {'; '.join(decision.reasons) or 'none'}")

    if smap.spans:
        click.echo("\nDetected spans:")
        for span in smap.spans:
            snippet = span.value[:30] + ("..." if len(span.value) > 30 else "")
            click.echo(
                f"  [{span.stage}] {click.style(span.entity_type, fg='yellow')} "
                f"conf={span.confidence:.2f}  value='{snippet}'"
            )

    if smap.code_blocks:
        click.echo("\nCode IP flags:")
        for blk in smap.code_blocks:
            click.echo(
                f"  ip_score={blk.ip_score:.2f}  "
                f"signals={', '.join(blk.signals)}"
            )

    if decision.action in (Action.REDACT, Action.BLOCK) and show_redacted:
        rr = upr.redact(smap)
        click.echo(f"\nRedacted prompt ({rr.num_redactions} substitution(s)):")
        click.echo(click.style(
            textwrap.fill(rr.redacted_prompt, width=80, subsequent_indent="  "),
            fg="green",
        ))


@cli.command()
def demo():
    """Run built-in demo prompts to show CADLP in action."""
    _print_banner()
    demos = [
        (
            "Clean prompt",
            "Can you explain the difference between LSTM and Transformer "
            "architectures for sequence modelling?",
        ),
        (
            "API key leakage",
            "I'm getting an error with my OpenAI integration. "
            "Here is my key: sk-abc123XYZdefGHIjklMNOpqrSTUvwx1234 "
            "Please help me debug it.",
        ),
        (
            "PII in operational context",
            "Please send a password reset email to john.doe@acmecorp.com "
            "for account ID EMP-00942.",
        ),
        (
            "Proprietary code",
            "I need help optimising this internal payment processor:\n"
            "```python\n"
            "from internal.payments import TierOnePlatinumRouter\n"
            "def process(txn):\n"
            "    router = TierOnePlatinumRouter(secret=config.PAYMENT_SECRET)\n"
            "    return router.dispatch(txn)\n"
            "```",
        ),
    ]

    csc    = ContextualSensitivityClassifier()
    upr    = UtilityPreservingRedactor()
    policy = PolicyEngine()

    for title, prompt in demos:
        click.echo("\n" + "=" * 60)
        click.echo(click.style(f"DEMO: {title}", bold=True))
        click.echo(f"Prompt: {prompt[:80]}{'...' if len(prompt) > 80 else ''}")

        smap     = csc.classify(prompt)
        decision = policy.evaluate(smap)

        click.echo(f"Decision: {_colour_action(decision.action)}")
        if smap.entity_types:
            click.echo(f"Entities: {', '.join(smap.entity_types)}")

        if decision.action == Action.REDACT:
            rr = upr.redact(smap)
            click.echo(f"Redacted: {rr.redacted_prompt[:100]}...")
        elif decision.action == Action.BLOCK:
            click.echo(click.style("BLOCKED: Prompt not forwarded to LLM.", fg="red"))


@cli.command()
@click.option("--dataset", "-d", required=True,
              type=click.Path(exists=True), help="Path to SEPAD-10K JSON file.")
@click.option("--threshold", "-t", default=0.50, show_default=True,
              type=float, help="Confidence threshold for positive classification.")
def eval_cmd(dataset: str, threshold: float):
    """Evaluate CADLP against a labelled dataset and print metrics."""
    import cadlp.eval.metrics as metrics_mod
    metrics_mod.run_evaluation(Path(dataset), threshold=threshold)


# Alias so 'cadlp eval' works as a command name
cli.add_command(eval_cmd, name="eval")


def main():
    cli()


if __name__ == "__main__":
    main()
