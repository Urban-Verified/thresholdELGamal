#!/usr/bin/env python3
"""
Admin TUI — Beautiful interactive terminal interface for managing elections.

Usage:
    python admin_tui.py --keyper-urls http://127.0.0.1:5001,http://127.0.0.1:5002,http://127.0.0.1:5003 --backend http://127.0.0.1:5000
"""

import argparse
import sys
import time
import threading
import requests
import logging

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import IntPrompt, Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TaskProgressColumn
from rich.text import Text
from rich.columns import Columns
from rich.rule import Rule
from rich.tree import Tree
from rich.live import Live
from rich.align import Align
from rich import box

from keyper import create_keyper_app
from backend import create_backend_app

console = Console()

# ── Server management ─────────────────────────────────────────────────

_running_servers = {}  # {label: {"thread": Thread, "port": int, "url": str}}

# ── Branding ──────────────────────────────────────────────────────────

BANNER = r"""
[bold magenta]  ╔══════════════════════════════════════════════════════════╗
  ║          [bold white]ELECTION ADMIN — CONTROL PANEL[bold magenta]              ║
  ║       [dim white]Threshold ElGamal · BLS12-381 G2[bold magenta]               ║
  ╚══════════════════════════════════════════════════════════╝[/]
"""


def fetch_status(backend_url):
    """Fetch election status from backend."""
    resp = requests.get(f"{backend_url}/election/status", timeout=10)
    resp.raise_for_status()
    return resp.json()


def fetch_result(backend_url):
    """Fetch election result from backend."""
    resp = requests.get(f"{backend_url}/election/result", timeout=10)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()


def show_dashboard(backend_url, keyper_urls):
    """Display the main admin dashboard with election state and keyper health."""
    try:
        status = fetch_status(backend_url)
    except requests.exceptions.ConnectionError:
        console.print("[red]Cannot connect to backend[/]")
        return

    phase = status["phase"]
    phase_styles = {
        "idle": ("dim white", "⏸ "),
        "setup": ("yellow", "⚙ "),
        "voting": ("green", "🗳"),
        "tallying": ("blue", "🔢"),
        "done": ("magenta", "✅"),
    }
    color, icon = phase_styles.get(phase, ("white", "  "))

    # Phase pipeline
    phases = ["idle", "setup", "voting", "tallying", "done"]
    pipeline = ""
    for p in phases:
        idx = phases.index(p)
        cur_idx = phases.index(phase)
        if p == phase:
            pipeline += f" [bold {color}]● {p.upper()}[/] "
        elif idx < cur_idx:
            pipeline += f" [green]✓ {p}[/] "
        else:
            pipeline += f" [dim]○ {p}[/] "
        if p != "done":
            pipeline += "[dim]→[/]"

    # Info panel
    info = Table(show_header=False, box=None, padding=(0, 2))
    info.add_column("key", style="bold cyan", width=18)
    info.add_column("value")
    info.add_row("Phase", f"[{color}]{icon} {phase.upper()}[/]")
    info.add_row("Candidates", f"[white]{status['num_candidates']}[/]  [dim]{', '.join(status.get('candidate_names', []))}[/]")
    info.add_row("Budget", f"[bold yellow]{status['budget']}[/]")
    info.add_row("Keypers (n)", f"[white]{status['n']}[/]")
    info.add_row("Threshold (t)", f"[white]{status['t']}[/]")
    info.add_row("Ballots", f"[bold cyan]{status['ballots_received']}[/]")
    info.add_row("Has Result", f"{'[green]Yes[/]' if status['has_result'] else '[dim]No[/]'}")

    from rich.console import Group
    from rich.text import Text as RichText
    console.print(Panel(
        Group(RichText.from_markup(f"  {pipeline}\n"), info),
        title="[bold white]Election Dashboard[/]",
        border_style="magenta",
        box=box.DOUBLE,
    ))

    # Keyper health check
    keyper_table = Table(title="[bold]Keyper Network[/]", box=box.ROUNDED,
                         border_style="cyan", title_style="bold white")
    keyper_table.add_column("ID", style="bold cyan", justify="center", width=4)
    keyper_table.add_column("URL", style="white")
    keyper_table.add_column("Status", justify="center", width=12)

    for i, url in enumerate(keyper_urls):
        kid = i + 1
        try:
            resp = requests.get(f"{url}/status", timeout=3)
            if resp.status_code == 200:
                keyper_table.add_row(str(kid), url, "[bold green]● ONLINE[/]")
            else:
                keyper_table.add_row(str(kid), url, "[yellow]● DEGRADED[/]")
        except Exception:
            keyper_table.add_row(str(kid), url, "[red]● OFFLINE[/]")

    console.print(keyper_table)


def create_election_wizard(backend_url, keyper_urls):
    """Interactive wizard for creating a new election."""
    console.print()
    console.print(Rule("[bold yellow]Create New Election[/]", style="yellow"))
    console.print()

    n = len(keyper_urls)
    console.print(f"  [dim]Detected [bold]{n}[/] keyper URLs[/]\n")

    default_t = n // 2
    t = IntPrompt.ask(
        f"  [bold]Threshold (t)[/] [dim](degree of polynomial; need t+1 for decrypt, 1 ≤ t < {n})[/]",
        default=default_t,
    )

    num_cand = IntPrompt.ask("  [bold]Number of candidates[/]", default=3)
    candidates = []
    for i in range(num_cand):
        name = Prompt.ask(f"  [bold]Candidate {i} name[/]", default=f"Candidate_{i}")
        candidates.append(name)

    budget = IntPrompt.ask("  [bold]Budget[/] [dim](1 = single-choice)[/]", default=1)

    # Confirm
    console.print()
    summary = Table(show_header=False, box=None)
    summary.add_column("", style="bold cyan")
    summary.add_column("")
    summary.add_row("Keypers (n)", str(n))
    summary.add_row("Threshold (t)", str(t))
    summary.add_row("Candidates", ", ".join(candidates))
    summary.add_row("Budget", str(budget))
    console.print(Panel(summary, title="[bold]New Election[/]", border_style="yellow"))

    if not Confirm.ask("  Create this election?", default=True):
        console.print("  [dim]Cancelled.[/]")
        return

    with console.status("[bold yellow]Creating election…[/]", spinner="dots12"):
        resp = requests.post(f"{backend_url}/election/create", json={
            "n": n,
            "t": t,
            "num_candidates": num_cand,
            "candidate_names": candidates,
            "budget": budget,
        }, timeout=10)

    if resp.status_code == 200:
        data = resp.json()
        console.print(Panel(
            f"[bold green]  ✓ Election created![/]\n\n"
            f"  [bold]Curve:[/] {data.get('curve')} {data.get('group', 'G2')}\n"
            f"  [bold]Phase:[/] {data['phase']}\n"
            f"  [bold]Keypers:[/] {data['n']} (threshold t={data['t']})\n"
            f"  [bold]Candidates:[/] {', '.join(data['candidate_names'])}\n"
            f"  [bold]Budget:[/] {data['budget']}\n\n"
            f"  [dim]Next step: Run the Distributed Key Generation (DKG).[/]",
            border_style="green",
            box=box.DOUBLE,
        ))
    else:
        console.print(f"\n[red]Error: {resp.json().get('error', 'Unknown')}[/]")


def run_dkg_tui(backend_url, keyper_urls):
    """Run DKG with live progress visualization."""
    console.print()
    console.print(Rule("[bold yellow]Distributed Key Generation (DKG)[/]", style="yellow"))
    console.print()

    n = len(keyper_urls)
    console.print(f"  [dim]Running Feldman VSS DKG with {n} keypers…[/]")
    console.print(f"  [dim]Protocol: Round 1 (polynomials) → P2P share distribution → Round 2 (verification)[/]")
    console.print(f"  [dim]Complaint mechanism enabled: malicious dealers will be excluded.[/]\n")

    # Show DKG architecture
    tree = Tree("[bold cyan]DKG Protocol[/]")
    r1 = tree.add("[white]Round 1 — Generate polynomials & commitments[/]")
    for i, url in enumerate(keyper_urls):
        r1.add(f"[dim]Keyper {i+1}: {url}[/]")
    r2 = tree.add("[white]Share Distribution — P2P encrypted shares[/]")
    r2.add(f"[dim]{n} × {n} = {n*n} total share transfers[/]")
    r3 = tree.add("[white]Round 2 — Verify shares against commitments[/]")
    r3.add("[dim]Any failed verification → complaint → dealer exclusion → retry[/]")
    console.print(Panel(tree, border_style="cyan", box=box.ROUNDED))

    if not Confirm.ask("  Start DKG?", default=True):
        console.print("  [dim]Cancelled.[/]")
        return

    console.print()

    # The actual DKG call (this triggers the full protocol server-side)
    with Progress(
        SpinnerColumn("dots12", style="cyan"),
        TextColumn("[bold white]{task.description}[/]"),
        TextColumn("[dim]{task.fields[detail]}[/]"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(
            "Running DKG protocol…",
            detail="Round 1 → Share distribution → Round 2 → Key derivation",
        )
        try:
            resp = requests.post(f"{backend_url}/election/dkg", json={}, timeout=120)
        except requests.exceptions.Timeout:
            progress.update(task, description="[red]DKG timed out[/]", detail="")
            console.print("\n[red]DKG protocol timed out after 120 seconds.[/]")
            return
        progress.update(task, completed=100)

    if resp.status_code == 200:
        data = resp.json()
        mpk_dict = data.get("mpk", {})
        mpk_hex = mpk_dict.get("x0", "")[:24] + "…" if mpk_dict else "N/A"

        share_table = Table(box=box.SIMPLE_HEAD, border_style="green", show_lines=False)
        share_table.add_column("Keyper", style="bold cyan", justify="center")
        share_table.add_column("MPK Share (fingerprint)", style="dim")

        for kid_str, share_dict in sorted(data.get("mpk_shares", {}).items()):
            fp = share_dict.get("x0", "")[:16] + "…"
            share_table.add_row(f"K{kid_str}", fp)

        console.print(Panel(
            f"[bold green]  ✓ DKG COMPLETE[/]\n\n"
            f"  [bold]Master Public Key:[/] [dim]{mpk_hex}[/]\n"
            f"  [bold]Phase:[/] {data['phase']}\n\n"
            f"{share_table}\n\n"
            f"  [dim]The election is now in VOTING phase.\n"
            f"  Share the master public key with voters.\n"
            f"  Secret key shares are distributed among keypers — no single entity can decrypt.[/]",
            border_style="green",
            box=box.DOUBLE,
            title="[bold green]DKG Success[/]",
        ))
    else:
        error = resp.json().get("error", "Unknown error")
        console.print(Panel(
            f"[bold red]  ✗ DKG FAILED[/]\n\n  {error}",
            border_style="red",
            box=box.DOUBLE,
        ))


def show_ballot_monitor(backend_url):
    """Display ballot count and live monitor."""
    console.print()
    console.print(Rule("[bold cyan]Ballot Monitor[/]", style="cyan"))
    console.print()

    try:
        status = fetch_status(backend_url)
    except requests.exceptions.ConnectionError:
        console.print("[red]Cannot connect to backend[/]")
        return

    count = status["ballots_received"]
    candidates = status.get("candidate_names", [])
    phase = status["phase"]

    if phase != "voting":
        console.print(f"  [yellow]Election is in phase '{phase}' — not currently accepting votes.[/]")
        console.print(f"  [dim]Total ballots recorded: {count}[/]")
        return

    # ASCII art ballot box
    ballot_art = f"""
  [cyan]┌─────────────────┐[/]
  [cyan]│[/]  [bold yellow]BALLOT BOX[/]      [cyan]│[/]
  [cyan]│[/]  ═══════════    [cyan]│[/]
  [cyan]│[/]                 [cyan]│[/]
  [cyan]│[/]   [bold white]{count:>5}[/] votes   [cyan]│[/]
  [cyan]│[/]                 [cyan]│[/]
  [cyan]└─────────────────┘[/]"""
    console.print(ballot_art)

    console.print(f"\n  [bold]Candidates:[/] {', '.join(candidates)}")
    console.print(f"  [bold]Budget:[/] {status['budget']}")
    console.print(f"  [bold]Keypers:[/] {status['n']} (t={status['t']})")
    console.print()
    console.print(f"  [dim]Votes are encrypted — the backend cannot see individual choices.[/]")
    console.print(f"  [dim]Each ballot verified: {status['num_candidates']} range proofs + 1 budget proof.[/]")

    # Live monitoring option
    if Confirm.ask("\n  Watch for new ballots? (Ctrl+C to stop)", default=False):
        last_count = count
        console.print()
        try:
            with Live(
                Panel(f"  [bold cyan]Watching…[/]  Ballots: [bold]{last_count}[/]", border_style="cyan"),
                console=console,
                refresh_per_second=1,
            ) as live:
                while True:
                    time.sleep(2)
                    try:
                        st = fetch_status(backend_url)
                        new_count = st["ballots_received"]
                        if new_count != last_count:
                            diff = new_count - last_count
                            live.update(Panel(
                                f"  [bold green]+ {diff} new ballot{'s' if diff > 1 else ''}![/]  "
                                f"Total: [bold]{new_count}[/]",
                                border_style="green",
                            ))
                            last_count = new_count
                        else:
                            live.update(Panel(
                                f"  [bold cyan]Watching…[/]  Ballots: [bold]{last_count}[/]  "
                                f"[dim](phase: {st['phase']})[/]",
                                border_style="cyan",
                            ))
                    except Exception:
                        live.update(Panel("  [red]Connection lost — retrying…[/]", border_style="red"))
        except KeyboardInterrupt:
            console.print("[dim]  Stopped watching.[/]")


def run_tally_tui(backend_url):
    """Run tally with visualization."""
    console.print()
    console.print(Rule("[bold blue]Tally & Threshold Decryption[/]", style="blue"))
    console.print()

    try:
        status = fetch_status(backend_url)
    except requests.exceptions.ConnectionError:
        console.print("[red]Cannot connect to backend[/]")
        return

    if status["phase"] != "voting":
        console.print(f"  [yellow]Cannot tally — election is in phase '{status['phase']}'[/]")
        return

    num_ballots = status["ballots_received"]
    if num_ballots == 0:
        console.print("  [yellow]No ballots to tally.[/]")
        return

    # Show tally plan
    tree = Tree("[bold blue]Tally Protocol[/]")
    agg = tree.add(f"[white]Homomorphic aggregation[/] [dim]({num_ballots} ballots × {status['num_candidates']} candidates)[/]")
    agg.add("[dim]Sum ciphertexts: Σ(C₁ⱼ), Σ(C₂ⱼ) for each candidate j[/]")
    dec = tree.add(f"[white]Threshold decryption[/] [dim](need {status['t']+1} of {status['n']} keypers)[/]")
    dec.add("[dim]Each keyper computes σ = sk · Σ(C₁ⱼ) + DLEQ proof[/]")
    dec.add("[dim]Lagrange interpolation → remove encryption mask[/]")
    rec = tree.add("[white]Discrete log recovery[/] [dim](Baby-step Giant-step)[/]")
    rec.add(f"[dim]Find m such that m·G = decrypted point, m ∈ [0, {num_ballots * status['budget']}][/]")
    console.print(Panel(tree, border_style="blue", box=box.ROUNDED))

    if not Confirm.ask(f"  Tally {num_ballots} ballots now?", default=True):
        console.print("  [dim]Cancelled.[/]")
        return

    console.print()

    with Progress(
        SpinnerColumn("dots12", style="blue"),
        TextColumn("[bold white]{task.description}[/]"),
        TextColumn("[dim]{task.fields[detail]}[/]"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(
            "Tallying votes…",
            detail="Aggregation → Decryption shares → DLEQ verify → BSGS recovery",
        )
        try:
            resp = requests.post(f"{backend_url}/election/tally", json={}, timeout=120)
        except requests.exceptions.Timeout:
            progress.update(task, description="[red]Tally timed out[/]", detail="")
            return
        progress.update(task, completed=100)

    if resp.status_code == 200:
        data = resp.json()
        results = data.get("results", {})
        total = data.get("total_ballots", 0)
        max_votes = max(results.values()) if results else 1

        console.print()
        console.print(Panel(
            "[bold green]  ✓ TALLY COMPLETE[/]",
            border_style="green",
            box=box.DOUBLE,
        ))
        console.print()

        # Results bar chart
        colors = ["cyan", "green", "yellow", "magenta", "blue", "red", "white"]
        bar_width = 40
        console.print(f"  [bold]Total ballots:[/] [cyan]{total}[/]\n")

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
                f"[bold yellow]  TIE[/] between: {', '.join(tied)} ({winner_votes} each)",
                border_style="yellow",
            ))
        else:
            console.print(Panel(
                f"  [bold green]🏆 WINNER: {winner}[/]  —  {winner_votes} votes ({winner_votes / total * 100:.1f}%)",
                border_style="green",
                box=box.DOUBLE,
            ))
    else:
        error = resp.json().get("error", "Unknown error")
        console.print(Panel(
            f"[bold red]  ✗ TALLY FAILED[/]\n\n  {error}",
            border_style="red",
            box=box.DOUBLE,
        ))


def start_servers_tui(backend_url, keyper_urls, backend_host, backend_port, keyper_host):
    """Launch backend and keyper Flask servers as background threads."""
    console.print()
    console.print(Rule("[bold green]Start Servers[/]", style="green"))
    console.print()

    # Check what's already running
    already_running = [label for label, info in _running_servers.items() if info["thread"].is_alive()]
    if already_running:
        console.print(f"  [yellow]Already running:[/] {', '.join(already_running)}")
        console.print()
        if not Confirm.ask("  Servers are already running. Skip to dashboard?", default=True):
            pass
        else:
            return

    # Show launch plan
    plan = Table(title="[bold]Launch Plan[/]", box=box.ROUNDED, border_style="green",
                 title_style="bold white")
    plan.add_column("Server", style="bold cyan")
    plan.add_column("URL", style="white")
    plan.add_row("Backend", backend_url)
    for i, url in enumerate(keyper_urls):
        plan.add_row(f"Keyper {i + 1}", url)
    console.print(plan)
    console.print()

    if not Confirm.ask(f"  Launch 1 backend + {len(keyper_urls)} keypers?", default=True):
        console.print("  [dim]Cancelled.[/]")
        return

    console.print()

    # Suppress Flask/Werkzeug request logging to keep TUI clean
    werkzeug_log = logging.getLogger("werkzeug")
    werkzeug_log.setLevel(logging.ERROR)

    # Launch keypers
    with Progress(
        SpinnerColumn("dots12", style="green"),
        TextColumn("[bold white]{task.description}[/]"),
        BarColumn(bar_width=30, style="green", complete_style="bold green"),
        TextColumn("[dim]{task.fields[detail]}[/]"),
        console=console,
    ) as progress:
        total = 1 + len(keyper_urls)
        task = progress.add_task("Launching servers", total=total, detail="")

        for i, url in enumerate(keyper_urls):
            kid = i + 1
            # Extract port from URL
            port = int(url.rsplit(":", 1)[1].rstrip("/"))
            label = f"keyper-{kid}"

            if label in _running_servers and _running_servers[label]["thread"].is_alive():
                progress.update(task, detail=f"Keyper {kid} already running")
                progress.advance(task)
                continue

            app = create_keyper_app(kid)
            t = threading.Thread(
                target=app.run,
                kwargs={"host": keyper_host, "port": port, "debug": False, "use_reloader": False},
                daemon=True,
                name=label,
            )
            t.start()
            _running_servers[label] = {"thread": t, "port": port, "url": url}
            progress.update(task, detail=f"Keyper {kid} on :{port}")
            progress.advance(task)
            time.sleep(0.3)  # brief pause for port binding

        # Launch backend
        label = "backend"
        if label in _running_servers and _running_servers[label]["thread"].is_alive():
            progress.update(task, detail="Backend already running")
            progress.advance(task)
        else:
            app = create_backend_app(keyper_urls)
            t = threading.Thread(
                target=app.run,
                kwargs={"host": backend_host, "port": backend_port, "debug": False, "use_reloader": False},
                daemon=True,
                name="backend",
            )
            t.start()
            _running_servers["backend"] = {"thread": t, "port": backend_port, "url": backend_url}
            progress.update(task, detail=f"Backend on :{backend_port}")
            progress.advance(task)
            time.sleep(0.5)  # give Flask a moment to bind

    # Verify all are reachable
    console.print()
    all_ok = True
    for i, url in enumerate(keyper_urls):
        try:
            resp = requests.get(f"{url}/status", timeout=3)
            if resp.status_code == 200:
                console.print(f"  [green]✓[/] Keyper {i + 1} [dim]({url})[/]")
            else:
                console.print(f"  [yellow]?[/] Keyper {i + 1} responded with {resp.status_code}")
                all_ok = False
        except Exception:
            console.print(f"  [red]✗[/] Keyper {i + 1} [dim]({url})[/] — not reachable")
            all_ok = False

    try:
        resp = requests.get(f"{backend_url}/election/status", timeout=3)
        if resp.status_code == 200:
            console.print(f"  [green]✓[/] Backend [dim]({backend_url})[/]")
        else:
            console.print(f"  [yellow]?[/] Backend responded with {resp.status_code}")
            all_ok = False
    except Exception:
        console.print(f"  [red]✗[/] Backend [dim]({backend_url})[/] — not reachable")
        all_ok = False

    console.print()
    if all_ok:
        console.print(Panel(
            f"[bold green]  ✓ ALL SERVERS RUNNING[/]\n\n"
            f"  [bold]{len(keyper_urls)}[/] keypers + [bold]1[/] backend\n"
            f"  [dim]Servers run as daemon threads — they stop when this TUI exits.[/]",
            border_style="green",
            box=box.DOUBLE,
        ))
    else:
        console.print(Panel(
            "[bold yellow]  ⚠ Some servers may not have started correctly.\n"
            "  Check if the ports are already in use.[/]",
            border_style="yellow",
        ))


def reset_election(backend_url):
    """Reset election state with confirmation."""
    console.print()
    console.print("[bold red]⚠  This will permanently delete all election state, ballots, and results.[/]")
    if not Confirm.ask("  Are you sure?", default=False):
        console.print("  [dim]Cancelled.[/]")
        return

    with console.status("[bold red]Resetting…[/]", spinner="dots12"):
        resp = requests.post(f"{backend_url}/election/reset", json={}, timeout=10)

    if resp.status_code == 200:
        console.print("[green]  ✓ Election reset. All state cleared.[/]")
    else:
        console.print(f"[red]  Error: {resp.json().get('error', 'Unknown')}[/]")


def main_menu(backend_url, keyper_urls, backend_host, backend_port, keyper_host):
    """Main interactive menu loop."""
    while True:
        # Show running server count in header
        alive = sum(1 for s in _running_servers.values() if s["thread"].is_alive())
        server_indicator = f"  [dim green]● {alive} servers running[/]" if alive else "  [dim red]● No servers running[/]"

        console.print()
        console.print(Rule("[bold magenta]Admin Menu[/]", style="dim"))
        console.print(server_indicator)
        console.print()
        console.print("  [bold green]0[/]  Start servers (backend + keypers)")
        console.print("  [bold magenta]1[/]  Dashboard & keyper health")
        console.print("  [bold magenta]2[/]  Create election")
        console.print("  [bold magenta]3[/]  Run DKG (distributed key generation)")
        console.print("  [bold magenta]4[/]  Monitor ballots")
        console.print("  [bold magenta]5[/]  Tally & decrypt results")
        console.print("  [bold magenta]6[/]  View results")
        console.print("  [bold red]7[/]  Reset election")
        console.print("  [bold magenta]q[/]  Quit")
        console.print()

        choice = Prompt.ask("[bold]Select[/]", choices=["0", "1", "2", "3", "4", "5", "6", "7", "q"], default="0")

        try:
            if choice == "0":
                start_servers_tui(backend_url, keyper_urls, backend_host, backend_port, keyper_host)
            elif choice == "1":
                show_dashboard(backend_url, keyper_urls)
            elif choice == "2":
                create_election_wizard(backend_url, keyper_urls)
            elif choice == "3":
                run_dkg_tui(backend_url, keyper_urls)
            elif choice == "4":
                show_ballot_monitor(backend_url)
            elif choice == "5":
                run_tally_tui(backend_url)
            elif choice == "6":
                show_result_view(backend_url)
            elif choice == "7":
                reset_election(backend_url)
            elif choice == "q":
                if alive:
                    console.print(f"\n[dim]Shutting down {alive} daemon server(s)…[/]")
                console.print("[dim]Goodbye.[/]")
                break
        except requests.exceptions.ConnectionError:
            console.print(f"\n[bold red]Cannot connect to backend at {backend_url}[/]")
            console.print("[dim]  Hint: Use option 0 to start servers first.[/]")
        except KeyboardInterrupt:
            console.print("\n[dim]Interrupted.[/]")
        except Exception as e:
            console.print(f"\n[red]Error: {e}[/]")


def show_result_view(backend_url):
    """Display stored results."""
    data = fetch_result(backend_url)
    if data is None:
        console.print("\n[yellow]  No results available yet.[/]")
        return

    results = data.get("results", {})
    total = data.get("total_ballots", 0)
    max_votes = max(results.values()) if results else 1

    console.print()
    console.print(Rule("[bold magenta]Election Results[/]", style="magenta"))
    console.print()
    console.print(f"  [bold]Total ballots:[/] [cyan]{total}[/]\n")

    colors = ["cyan", "green", "yellow", "magenta", "blue", "red", "white"]
    bar_width = 40
    for i, (name, count) in enumerate(results.items()):
        color = colors[i % len(colors)]
        filled = int((count / max_votes) * bar_width) if max_votes > 0 else 0
        bar = f"[{color}]{'█' * filled}[/][dim]{'░' * (bar_width - filled)}[/]"
        pct = (count / (total if total > 0 else 1)) * 100
        console.print(f"  [bold]{name:>20}[/]  {bar}  [bold {color}]{count}[/] [dim]({pct:.1f}%)[/]")

    console.print()
    winner = max(results, key=results.get)
    winner_votes = results[winner]
    tied = [n for n, v in results.items() if v == winner_votes]
    if len(tied) > 1:
        console.print(Panel(
            f"[bold yellow]  TIE[/] between: {', '.join(tied)} ({winner_votes} each)",
            border_style="yellow",
        ))
    else:
        console.print(Panel(
            f"  [bold green]🏆 WINNER: {winner}[/]  —  {winner_votes} votes",
            border_style="green",
            box=box.DOUBLE,
        ))


def main():
    parser = argparse.ArgumentParser(
        description="Election Admin TUI",
        epilog="Example: python admin_tui.py --num-keypers 3",
    )
    parser.add_argument("--backend", default=None,
                        help="Backend server URL (default: http://<host>:<backend-port>)")
    parser.add_argument("--backend-port", type=int, default=5000,
                        help="Backend port (default: 5000)")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Host to bind all servers to (default: 127.0.0.1)")
    parser.add_argument("--keyper-urls", default=None,
                        help="Comma-separated keyper URLs (auto-generated if omitted)")
    parser.add_argument("--num-keypers", type=int, default=3,
                        help="Number of keypers to auto-configure (default: 3, used when --keyper-urls is omitted)")
    parser.add_argument("--keyper-base-port", type=int, default=5001,
                        help="Starting port for auto-configured keypers (default: 5001)")
    args = parser.parse_args()

    host = args.host
    backend_port = args.backend_port
    backend_url = args.backend or f"http://{host}:{backend_port}"

    if args.keyper_urls:
        keyper_urls = [u.strip() for u in args.keyper_urls.split(",")]
    else:
        keyper_urls = [
            f"http://{host}:{args.keyper_base_port + i}"
            for i in range(args.num_keypers)
        ]

    console.print(BANNER)
    console.print(Align.center(f"[dim]Backend: {backend_url}  |  Keypers: {len(keyper_urls)}[/]"))

    main_menu(backend_url, keyper_urls, host, backend_port, host)


if __name__ == "__main__":
    main()
