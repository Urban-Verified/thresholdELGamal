#!/usr/bin/env python3
"""
Voter TUI — Beautiful interactive terminal interface for casting encrypted votes.

Usage:
    python voter_tui.py --backend http://127.0.0.1:5000
"""

import argparse
import sys
import time
import requests

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import IntPrompt, Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.text import Text
from rich.columns import Columns
from rich.rule import Rule
from rich.align import Align
from rich import box

from crypto.primitives import CURVE_ORDER, dict_to_point, point_to_dict, point_to_bytes
from crypto.elgamal import encrypt, aggregate_ciphertexts
from crypto.proofs import prove_range, prove_exact_budget

console = Console()

# ── Branding ──────────────────────────────────────────────────────────

BANNER = r"""
[bold cyan]  ╔══════════════════════════════════════════════════════════╗
  ║           [bold white]THRESHOLD ELGAMAL VOTING SYSTEM[bold cyan]            ║
  ║        [dim white]Cryptographic Ballot — BLS12-381 G2[bold cyan]            ║
  ╚══════════════════════════════════════════════════════════╝[/]
"""

LOCK_ART = """[dim cyan]
    ┌───────┐
    │ ░░░░░ │  Your vote is encrypted
    │ ░ZK░░ │  with zero-knowledge proofs.
    │ ░░░░░ │  Nobody can see your choices.
    └───┬───┘
        │
    ╔═══╧═══╗
    ║ ████  ║
    ║ ████  ║
    ╚═══════╝[/]"""


def fetch_params(backend_url):
    """Fetch and return election parameters."""
    resp = requests.get(f"{backend_url}/election/params", timeout=10)
    resp.raise_for_status()
    return resp.json()


def show_election_info(params):
    """Display election parameters in a rich panel."""
    phase_colors = {
        "idle": "dim white", "setup": "yellow", "voting": "green",
        "tallying": "blue", "done": "magenta",
    }
    phase = params["phase"]
    pc = phase_colors.get(phase, "white")

    info_table = Table(show_header=False, box=None, padding=(0, 2))
    info_table.add_column("key", style="bold cyan", width=18)
    info_table.add_column("value")

    info_table.add_row("Phase", f"[{pc}]● {phase.upper()}[/]")
    info_table.add_row("Curve", f"[white]{params.get('curve', 'BLS12-381')} {params.get('group', 'G2')}[/]")
    info_table.add_row("Election ID", f"[dim]{params.get('election_id', 'N/A')[:16]}…[/]")
    info_table.add_row("Keypers", f"[white]{params['n']}[/] [dim](threshold t={params['t']}, need {params['t']+1})[/]")
    info_table.add_row("Budget", f"[bold yellow]{params['budget']}[/] [dim]point{'s' if params['budget'] != 1 else ''}[/]")
    mpk_hex = "Not set"
    if params.get("mpk") and not params["mpk"].get("identity"):
        mpk_hex = params["mpk"].get("x0", "")[:18] + "…"
    info_table.add_row("Public Key (mpk)", f"[dim]{mpk_hex}[/]")

    console.print(Panel(info_table, title="[bold white]Election Parameters[/]", border_style="cyan", box=box.DOUBLE))


def show_candidates(params):
    """Display candidates in a table."""
    table = Table(title="[bold]Candidates[/]", box=box.ROUNDED, border_style="cyan",
                  show_lines=True, title_style="bold white")
    table.add_column("#", style="bold cyan", justify="center", width=4)
    table.add_column("Name", style="bold white", min_width=20)
    table.add_column("Your Vote", style="bold yellow", justify="center", width=12)

    for i, name in enumerate(params.get("candidate_names", [])):
        table.add_row(str(i), name, "—")
    console.print(table)


def collect_votes_interactive(params):
    """Interactive vote collection with live validation."""
    candidates = params.get("candidate_names", [])
    B = params["budget"]
    num_cand = params["num_candidates"]

    console.print()
    if B == 1:
        console.print("[bold cyan]Single-choice election[/] — Pick one candidate.\n")
        for i, name in enumerate(candidates):
            console.print(f"  [bold cyan]{i}[/]  {name}")
        console.print()

        while True:
            choice = IntPrompt.ask(
                "[bold]Enter candidate number[/]",
                choices=[str(i) for i in range(num_cand)],
            )
            vote_vector = [0] * num_cand
            vote_vector[choice] = 1

            console.print(f"\n  [bold green]✓[/] You selected [bold]{candidates[choice]}[/]")
            if Confirm.ask("  Confirm this vote?", default=True):
                return vote_vector
    else:
        console.print(f"[bold cyan]Budget election[/] — Distribute [bold yellow]{B}[/] points across candidates.\n")

        while True:
            vote_vector = []
            remaining = B

            for i, name in enumerate(candidates):
                max_val = remaining if i < num_cand - 1 else remaining
                if i == num_cand - 1:
                    # Last candidate gets whatever remains
                    console.print(f"  [bold cyan]{name}[/]: [bold yellow]{remaining}[/] [dim](auto-assigned remaining)[/]")
                    vote_vector.append(remaining)
                else:
                    val = IntPrompt.ask(
                        f"  [bold cyan]{name}[/] [dim](0–{max_val}, {remaining} remaining)[/]",
                        default=0,
                    )
                    val = max(0, min(val, max_val))
                    vote_vector.append(val)
                    remaining -= val

            # Show summary
            console.print()
            summary = Table(box=box.SIMPLE, show_header=False)
            summary.add_column("candidate", style="white")
            summary.add_column("points", style="bold yellow", justify="right")
            summary.add_column("bar", style="cyan")
            for i, name in enumerate(candidates):
                bar = "█" * vote_vector[i] + "░" * (B - vote_vector[i])
                summary.add_row(name, str(vote_vector[i]), bar)
            console.print(Panel(summary, title="[bold]Your Ballot[/]", border_style="yellow"))

            if Confirm.ask("  Confirm this ballot?", default=True):
                return vote_vector
            console.print("[dim]  Let's try again...[/]\n")


def encrypt_and_submit(backend_url, params, vote_vector):
    """Encrypt ballot, generate proofs, and submit — with live visualization."""
    mpk = dict_to_point(params["mpk"])
    B = params["budget"]
    num_cand = params["num_candidates"]
    candidates = params.get("candidate_names", [])
    election_id = params.get("election_id", "")

    console.print()
    console.print(Rule("[bold cyan]Cryptographic Operations[/]", style="cyan"))
    console.print()

    console.print(Columns([Panel(LOCK_ART, border_style="cyan", box=box.ROUNDED)], align="center"))
    console.print()

    # ── Step 1: Encrypt ──────────────────────────────────────
    ciphertexts = []
    randomness = []

    with Progress(
        SpinnerColumn("dots12", style="cyan"),
        TextColumn("[bold white]{task.description}[/]"),
        BarColumn(bar_width=30, style="cyan", complete_style="bold green"),
        TextColumn("[dim]{task.fields[detail]}[/]"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Encrypting votes", total=num_cand, detail="")
        for j in range(num_cand):
            progress.update(task, detail=f"{candidates[j]} (m={vote_vector[j]})")
            C1, C2, r = encrypt(mpk, vote_vector[j])
            ciphertexts.append((C1, C2))
            randomness.append(r)
            progress.advance(task)

    # Show ciphertext fingerprints
    ct_table = Table(box=box.SIMPLE_HEAD, border_style="dim", show_lines=False)
    ct_table.add_column("Candidate", style="white")
    ct_table.add_column("C₁ (fingerprint)", style="dim cyan")
    ct_table.add_column("C₂ (fingerprint)", style="dim cyan")
    for j in range(num_cand):
        c1_hex = point_to_bytes(ciphertexts[j][0])[:8].hex()
        c2_hex = point_to_bytes(ciphertexts[j][1])[:8].hex()
        ct_table.add_row(candidates[j], f"{c1_hex}…", f"{c2_hex}…")
    console.print(Panel(ct_table, title="[bold]Ciphertexts[/]", border_style="green", box=box.ROUNDED))

    # ── Step 2: Range Proofs ──────────────────────────────────
    range_proofs = []
    with Progress(
        SpinnerColumn("dots12", style="cyan"),
        TextColumn("[bold white]{task.description}[/]"),
        BarColumn(bar_width=30, style="cyan", complete_style="bold green"),
        TextColumn("[dim]{task.fields[detail]}[/]"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Generating range proofs", total=num_cand, detail="")
        for j in range(num_cand):
            progress.update(task, detail=f"{candidates[j]}: v∈{{0,…,{B}}}")
            C1, C2 = ciphertexts[j]
            proof = prove_range(mpk, C1, C2, vote_vector[j], randomness[j], B, election_id=election_id)
            range_proofs.append(proof)
            progress.advance(task)

    console.print(f"  [green]✓[/] {num_cand} range proofs generated [dim]({B+1}-branch OR-DLEQ each)[/]")

    # ── Step 3: Budget Proof ──────────────────────────────────
    with Progress(
        SpinnerColumn("dots12", style="cyan"),
        TextColumn("[bold white]{task.description}[/]"),
        TextColumn("[dim]{task.fields[detail]}[/]"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Generating budget proof", total=1, detail=f"Σvⱼ = {B}")
        sum_ct = aggregate_ciphertexts(ciphertexts)
        r_sum = sum(randomness) % CURVE_ORDER
        budget_proof = prove_exact_budget(mpk, sum_ct[0], sum_ct[1], B, r_sum, election_id=election_id)
        progress.advance(task)

    console.print(f"  [green]✓[/] Budget proof generated [dim](DLEQ: Σvⱼ = {B})[/]")

    # ── Step 4: Submit ────────────────────────────────────────
    payload = {
        "ciphertexts": [
            {"c1": point_to_dict(ct[0]), "c2": point_to_dict(ct[1])} for ct in ciphertexts
        ],
        "range_proofs": [
            [{"e": str(e), "z": str(z)} for (e, z) in proof]
            for proof in range_proofs
        ],
        "budget_proof": {"e": str(budget_proof[0]), "z": str(budget_proof[1])},
    }

    console.print()
    with console.status("[bold cyan]Submitting encrypted ballot to backend…[/]", spinner="dots12"):
        resp = requests.post(f"{backend_url}/election/vote", json=payload, timeout=30)
        result = resp.json()

    if resp.status_code == 200 and result.get("status") == "ok":
        console.print()
        console.print(Panel(
            f"[bold green]  ✓ VOTE ACCEPTED[/]\n\n"
            f"  Ballot #{result.get('ballot_number', '?')}\n"
            f"  [dim]Your vote is encrypted and verified.\n"
            f"  The backend confirmed all ZK proofs are valid.\n"
            f"  Nobody — not even the backend — knows your choices.[/]",
            border_style="green",
            box=box.DOUBLE,
            title="[bold green]Success[/]",
        ))
        return True
    else:
        console.print()
        console.print(Panel(
            f"[bold red]  ✗ VOTE REJECTED[/]\n\n"
            f"  {result.get('error', 'Unknown error')}",
            border_style="red",
            box=box.DOUBLE,
        ))
        return False


def show_result_tui(backend_url):
    """Display election results with a bar chart visualization."""
    try:
        resp = requests.get(f"{backend_url}/election/result", timeout=10)
    except requests.exceptions.ConnectionError:
        console.print("[red]Cannot connect to backend[/]")
        return

    if resp.status_code == 404:
        console.print(Panel(
            "[yellow]No results available yet.[/]\n[dim]The election may still be in progress.[/]",
            border_style="yellow", box=box.ROUNDED,
        ))
        return

    resp.raise_for_status()
    data = resp.json()
    results = data.get("results", {})
    total = data.get("total_ballots", 0)

    if not results:
        console.print("[yellow]No results.[/]")
        return

    max_votes = max(results.values()) if results else 1

    console.print()
    console.print(Rule("[bold magenta]Election Results[/]", style="magenta"))
    console.print()
    console.print(f"  [bold]Total ballots cast:[/] [cyan]{total}[/]")
    console.print()

    # Bar chart
    colors = ["cyan", "green", "yellow", "magenta", "blue", "red", "white"]
    bar_width = 40
    for i, (name, count) in enumerate(results.items()):
        color = colors[i % len(colors)]
        filled = int((count / max_votes) * bar_width) if max_votes > 0 else 0
        bar = f"[{color}]{'█' * filled}[/][dim]{'░' * (bar_width - filled)}[/]"
        pct = (count / (total if total > 0 else 1)) * 100
        console.print(f"  [bold]{name:>20}[/]  {bar}  [bold {color}]{count}[/] [dim]({pct:.1f}%)[/]")

    # Winner
    console.print()
    winner = max(results, key=results.get)
    winner_votes = results[winner]
    tied = [n for n, v in results.items() if v == winner_votes]
    if len(tied) > 1:
        console.print(Panel(
            f"[bold yellow]TIE[/] between: {', '.join(tied)} ({winner_votes} votes each)",
            border_style="yellow", box=box.ROUNDED,
        ))
    else:
        console.print(Panel(
            f"[bold green]WINNER: {winner}[/] with [bold]{winner_votes}[/] votes",
            border_style="green", box=box.DOUBLE,
        ))


def show_status_tui(backend_url):
    """Display current election status."""
    try:
        resp = requests.get(f"{backend_url}/election/status", timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.ConnectionError:
        console.print("[red]Cannot connect to backend[/]")
        return

    phase = data["phase"]
    phase_icons = {
        "idle": "⏸ ", "setup": "⚙ ", "voting": "🗳",
        "tallying": "🔢", "done": "✅",
    }
    icon = phase_icons.get(phase, "  ")

    # Phase pipeline
    phases = ["idle", "setup", "voting", "tallying", "done"]
    pipeline = ""
    for p in phases:
        if p == phase:
            pipeline += f" [bold green]● {p.upper()}[/] "
        elif phases.index(p) < phases.index(phase):
            pipeline += f" [dim green]● {p}[/] "
        else:
            pipeline += f" [dim]○ {p}[/] "
        if p != "done":
            pipeline += "[dim]→[/]"

    console.print()
    console.print(Panel(
        f"  {pipeline}\n\n"
        f"  [bold]Candidates:[/]   {data['num_candidates']}  [dim]({', '.join(data.get('candidate_names', []))})[/]\n"
        f"  [bold]Budget:[/]       {data['budget']}\n"
        f"  [bold]Keypers:[/]      {data['n']} [dim](t={data['t']})[/]\n"
        f"  [bold]Ballots:[/]      [cyan]{data['ballots_received']}[/]\n"
        f"  [bold]Has result:[/]   {'[green]Yes[/]' if data['has_result'] else '[dim]No[/]'}",
        title=f"[bold white]{icon} Election Status[/]",
        border_style="cyan",
        box=box.DOUBLE,
    ))


def main_menu(backend_url):
    """Main interactive menu loop."""
    while True:
        console.print()
        console.print("[bold cyan]What would you like to do?[/]\n")
        console.print("  [bold cyan]1[/]  View election info")
        console.print("  [bold cyan]2[/]  Cast a vote")
        console.print("  [bold cyan]3[/]  View results")
        console.print("  [bold cyan]4[/]  View status")
        console.print("  [bold cyan]q[/]  Quit")
        console.print()

        choice = Prompt.ask("[bold]Select[/]", choices=["1", "2", "3", "4", "q"], default="2")

        try:
            if choice == "1":
                params = fetch_params(backend_url)
                show_election_info(params)
                show_candidates(params)

            elif choice == "2":
                params = fetch_params(backend_url)
                if params["phase"] != "voting":
                    console.print(f"\n[yellow]Election is in phase '[bold]{params['phase']}[/]' — not accepting votes.[/]")
                    continue
                show_election_info(params)
                vote_vector = collect_votes_interactive(params)
                encrypt_and_submit(backend_url, params, vote_vector)

            elif choice == "3":
                show_result_tui(backend_url)

            elif choice == "4":
                show_status_tui(backend_url)

            elif choice == "q":
                console.print("\n[dim]Goodbye.[/]")
                break

        except requests.exceptions.ConnectionError:
            console.print(f"\n[bold red]Cannot connect to backend at {backend_url}[/]")
        except KeyboardInterrupt:
            console.print("\n[dim]Interrupted.[/]")
            break
        except Exception as e:
            console.print(f"\n[red]Error: {e}[/]")


def main():
    parser = argparse.ArgumentParser(description="Voter TUI for threshold ElGamal voting")
    parser.add_argument("--backend", default="http://127.0.0.1:5000", help="Backend server URL")
    args = parser.parse_args()

    console.print(BANNER)
    console.print(Align.center(f"[dim]Backend: {args.backend}[/]"))

    main_menu(args.backend)


if __name__ == "__main__":
    main()
