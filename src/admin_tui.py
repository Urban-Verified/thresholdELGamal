#!/usr/bin/env python3
"""
Admin TUI — Beautiful interactive terminal interface for managing elections.

Usage:
    python admin_tui.py --num-keypers 3
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
from wr_oracle import create_wr_oracle_app
from vote_proxy import create_vote_proxy_app
from eth_account import Account
from sdk_compat import schnorr_keygen
from crypto.primitives import g1_to_compressed

import dkg_coordinator
import tally_aggregator
import voter
import chain_setup
from chain_setup import ANVIL_KEYS, anvil_address
from eth_client import EthChain, ElectionClient

console = Console()

# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

def _run_flask_quiet(app, *, host: str, port: int) -> None:
    """Run a Flask dev server with reduced log spam.

    Avoids redirecting ``sys.stdout``/``sys.stderr`` because that is global and
    would break the interactive TUI prompt output.
    """
    # Suppress werkzeug request logs.
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    # Best-effort suppression of Flask's startup banner (implementation detail).
    try:
        import flask.cli  # type: ignore
        flask.cli.show_server_banner = lambda *args, **kwargs: None  # type: ignore[attr-defined]
    except Exception:
        pass
    app.run(host=host, port=port, debug=False, use_reloader=False)

# ── Server management ─────────────────────────────────────────────────

_running_servers = {}  # {label: {"thread": Thread, "port": int, "url": str}}

# ── On-chain state ────────────────────────────────────────────────────
# Populated when the user starts the chain via menu item 'c'.
_chain_state: dict = {
    "anvil": None,           # AnvilProcess | None
    "chain": None,           # EthChain | None
    "admin_key": None,       # private key string
    "admin_addr": None,
    "tally_key": None,       # private key for TALLY_AGGREGATOR_ROLE
    "tally_addr": None,
    "proxy_key": None,       # private key for VOTE_PROXY_ROLE
    "proxy_addr": None,
    "keyper_keys": [],       # one private key per keyper, in member-index order
    "keyper_addrs": [],
    "keyper_set_addr": None,
    "registry_addr": None,
    "elections": [],         # list of Election addresses, in publish order
    # Human-readable candidate labels for the latest published election; reset
    # on each new publishElection. TUI-only — not persisted on chain.
    "candidate_names": [],
    # WR oracle — Schnorr-on-G1 keypair (BLS12-381), separate from anvil keys.
    "wr_sk": None,           # int (Schnorr secret on G1)
    "wr_pk": None,           # bytes (48-byte compressed G1, written to Election.pkWR)
    "wr_url": None,          # http://127.0.0.1:<port>/  for the wr_oracle process
}


# Deterministic WR seed for the admin-TUI demo. Distinct from the pytest
# fixture's seed so the demo and the test suite use different WR identities.
_WR_SEED_INT = int.from_bytes(b"WR-admin-tui" + b"\x00" * 20, "big") + 1

# ── Branding ──────────────────────────────────────────────────────────

BANNER = r"""
[bold magenta]  ╔══════════════════════════════════════════════════════════╗
  ║          [bold white]ELECTION ADMIN — CONTROL PANEL[bold magenta]              ║
  ║       [dim white]Threshold ElGamal · BLS12-381 G2[bold magenta]               ║
  ╚══════════════════════════════════════════════════════════╝[/]
"""


def run_dkg_tui(keyper_urls):
    """Run DKG across keypers and publish the DKG result on-chain."""
    console.print()
    console.print(Rule("[bold cyan]DKG coordinator (on-chain publish)[/]", style="cyan"))
    console.print()

    if _chain_state["chain"] is None or not _chain_state["elections"]:
        console.print("[yellow]  Start chain (c) and publish an election (e) first.[/]")
        return

    election_addr = _chain_state["elections"][-1]
    election = ElectionClient(_chain_state["chain"], election_addr)
    info = election.get_election()

    n = len(keyper_urls)
    threshold_t = int(info["config"]["thresholdT"])
    t_degree = max(0, threshold_t - 1)
    election_id = f"election-{int(info['config']['electionId'])}"

    console.print(Panel(
        f"[bold]Election:[/] [dim]{election_addr}[/]\n"
        f"[bold]n:[/] {n}   [bold]thresholdT:[/] {threshold_t}   [bold]t (degree):[/] {t_degree}\n"
        f"[bold]keyper election_id:[/] {election_id}",
        border_style="cyan",
        box=box.ROUNDED,
    ))
    if not Confirm.ask("  Start DKG now?", default=True):
        console.print("  [dim]Cancelled.[/]")
        return

    with Progress(
        SpinnerColumn("dots12", style="cyan"),
        TextColumn("[bold white]{task.description}[/]"),
        TextColumn("[dim]{task.fields[detail]}[/]"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Running DKG…", detail="round1 → commitments → shares → round2 → publish_on_chain")
        try:
            dkg_coordinator.run_dkg(
                keyper_urls=keyper_urls,
                election_id=election_id,
                election_address=election_addr,
                n=n,
                t=t_degree,
                timeout=120.0,
                sleep_between=0.0,
                verbose=True,
            )
        finally:
            progress.update(task, completed=100, detail="Done")

    console.print(Panel(
        "[bold green]  ✓ DKG complete and published on-chain[/]",
        border_style="green",
        box=box.DOUBLE,
    ))


def start_servers_tui(keyper_urls, keyper_host, *, confirm: bool = True):
    """Launch keyper Flask servers as background threads."""
    console.print()
    console.print(Rule("[bold green]Start Keypers[/]", style="green"))
    console.print()

    if not _chain_state.get("keyper_keys"):
        console.print(
            "[yellow]  Start chain first (option c).[/]\n"
            "  [dim]Reason: keypers must use the deterministic anvil keys that were\n"
            "  registered in the on-chain KeyperSet. If you start keypers before the\n"
            "  chain is up, they generate random Ethereum identities and will not\n"
            "  match the on-chain committee.[/]",
        )
        return

    # Check what's already running
    already_running = [
        label
        for label, info in _running_servers.items()
        if label.startswith("keyper-") and info["thread"].is_alive()
    ]
    if already_running:
        console.print(f"  [yellow]Already running:[/] {', '.join(already_running)}")
        console.print()
        if not Confirm.ask("  Keypers are already running. Return to menu?", default=True):
            pass
        else:
            return

    # Show launch plan
    plan = Table(title="[bold]Launch Plan[/]", box=box.ROUNDED, border_style="green",
                 title_style="bold white")
    plan.add_column("Server", style="bold cyan")
    plan.add_column("URL", style="white")
    for i, url in enumerate(keyper_urls):
        plan.add_row(f"Keyper {i + 1}", url)
    console.print(plan)
    console.print()

    if confirm:
        if not Confirm.ask(f"  Launch {len(keyper_urls)} keypers?", default=True):
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
        task = progress.add_task("Launching keypers", total=len(keyper_urls), detail="")

        for i, url in enumerate(keyper_urls):
            kid = i + 1
            # Extract port from URL
            port = int(url.rsplit(":", 1)[1].rstrip("/"))
            label = f"keyper-{kid}"

            if label in _running_servers and _running_servers[label]["thread"].is_alive():
                progress.update(task, detail=f"Keyper {kid} already running")
                progress.advance(task)
                continue

            signing_key = None
            if _chain_state.get("keyper_keys"):
                if i < len(_chain_state["keyper_keys"]):
                    signing_key = _chain_state["keyper_keys"][i]
            chain_cfg = None
            if _chain_state.get("anvil") is not None and signing_key is not None:
                chain_cfg = {"rpc_url": _chain_state["anvil"].rpc_url, "private_key": signing_key}
            app = create_keyper_app(kid, chain_config=chain_cfg, signing_key=signing_key)
            t = threading.Thread(
                target=lambda a=app, h=keyper_host, p=port: _run_flask_quiet(a, host=h, port=p),
                daemon=True,
                name=label,
            )
            t.start()
            _running_servers[label] = {"thread": t, "port": port, "url": url}
            progress.update(task, detail=f"Keyper {kid} on :{port}")
            progress.advance(task)
            time.sleep(0.3)  # brief pause for port binding

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

    console.print()
    if all_ok:
        console.print(Panel(
            f"[bold green]  ✓ KEYPERS RUNNING[/]\n\n"
            f"  [bold]{len(keyper_urls)}[/] keypers\n"
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


def start_chain_tui(num_keypers: int, threshold: int, anvil_port: int):
    """Start anvil and deploy KeyperSet + ElectionRegistry."""
    console.print()
    console.print(Rule("[bold cyan]On-chain bootstrap[/]", style="cyan"))
    console.print()

    if any(info["thread"].is_alive() for info in _running_servers.values()):
        console.print(
            "[yellow]  Note: keyper servers are already running.[/]\n"
            "  [dim]If you started them before the chain, their Ethereum addresses\n"
            "  will not match the KeyperSet members. In that case, quit and restart\n"
            "  the TUI, then run: c (start chain) → k (start keypers).[/]",
        )

    if _chain_state["anvil"] is not None:
        console.print("[yellow]  Chain already running. Stop it first (option x).[/]")
        return

    # Role assignment (deterministic anvil keys; see PLAN.md decision D).
    admin_key = ANVIL_KEYS[0]
    tally_key = ANVIL_KEYS[1]
    proxy_key = ANVIL_KEYS[2]
    keyper_keys = list(ANVIL_KEYS[3:3 + num_keypers])
    if len(keyper_keys) < num_keypers:
        console.print(f"[red]  Need {num_keypers} keypers but only {len(keyper_keys)} anvil keys remain.[/]")
        return

    keyper_addrs = [anvil_address(k) for k in keyper_keys]

    # WR oracle: deterministic Schnorr-on-G1 keypair (BLS12-381). Lives
    # outside ANVIL_KEYS because it's not an Ethereum secp256k1 keypair.
    wr_sk, wr_vk = schnorr_keygen(_WR_SEED_INT)
    wr_pk = g1_to_compressed(wr_vk)

    plan = Table(box=box.ROUNDED, border_style="cyan")
    plan.add_column("Role", style="bold cyan")
    plan.add_column("Address / Key", style="dim")
    plan.add_row("anvil RPC", f"http://127.0.0.1:{anvil_port}")
    plan.add_row("admin (Vote Manager)", anvil_address(admin_key))
    plan.add_row("tally aggregator", anvil_address(tally_key))
    plan.add_row("vote proxy", anvil_address(proxy_key))
    for i, addr in enumerate(keyper_addrs, start=1):
        plan.add_row(f"keyper {i}", addr)
    plan.add_row("threshold", f"{threshold} of {num_keypers}")
    plan.add_row("WR vk (G1)", wr_pk.hex()[:48] + "…")
    console.print(plan)
    if not Confirm.ask("  Launch anvil and deploy contracts?", default=True):
        console.print("  [dim]Cancelled.[/]")
        return

    with Progress(
        SpinnerColumn("dots12", style="cyan"),
        TextColumn("[bold white]{task.description}[/]"),
        TextColumn("[dim]{task.fields[detail]}[/]"),
        console=console,
    ) as progress:
        task = progress.add_task("Launching anvil…", detail="")
        try:
            anvil = chain_setup.start_anvil(port=anvil_port, log_path="/tmp/anvil.log")
        except Exception as e:
            progress.update(task, description="[red]anvil failed[/]", detail=str(e))
            console.print(f"\n[red]Failed to start anvil: {e}[/]")
            return
        progress.update(task, description="anvil up", detail=anvil.rpc_url)

        progress.update(task, description="Deploying KeyperSet…", detail="forge create")
        try:
            ks_addr = chain_setup.deploy_keyper_set(
                rpc_url=anvil.rpc_url, deployer_key=admin_key,
                members=keyper_addrs, threshold=threshold,
            )
        except Exception as e:
            chain_setup.stop_anvil(anvil)
            console.print(f"\n[red]KeyperSet deploy failed: {e}[/]")
            return
        progress.update(task, description="KeyperSet deployed", detail=ks_addr)

        progress.update(task, description="Deploying ElectionRegistry…", detail="forge create")
        try:
            reg_addr = chain_setup.deploy_registry(
                rpc_url=anvil.rpc_url, deployer_key=admin_key,
                admin=anvil_address(admin_key),
            )
        except Exception as e:
            chain_setup.stop_anvil(anvil)
            console.print(f"\n[red]Registry deploy failed: {e}[/]")
            return
        progress.update(task, description="Registry deployed", detail=reg_addr)

    chain = EthChain.connect(anvil.rpc_url, private_key=admin_key)

    wr_port = 5300
    wr_url = f"http://127.0.0.1:{wr_port}"
    _chain_state.update({
        "anvil": anvil,
        "chain": chain,
        "admin_key": admin_key, "admin_addr": anvil_address(admin_key),
        "tally_key": tally_key, "tally_addr": anvil_address(tally_key),
        "proxy_key": proxy_key, "proxy_addr": anvil_address(proxy_key),
        "keyper_keys": keyper_keys, "keyper_addrs": keyper_addrs,
        "keyper_set_addr": ks_addr,
        "registry_addr": reg_addr,
        "elections": [],
        "wr_sk": wr_sk, "wr_pk": wr_pk, "wr_url": wr_url,
    })

    console.print(Panel(
        f"[bold green]  ✓ Chain ready[/]\n\n"
        f"  [bold]anvil:[/]            [dim]{anvil.rpc_url}[/]\n"
        f"  [bold]KeyperSet:[/]        [dim]{ks_addr}[/]\n"
        f"  [bold]ElectionRegistry:[/] [dim]{reg_addr}[/]\n"
        f"  [bold]WR oracle:[/]        [dim]{wr_url}[/]  [dim](not started yet)[/]\n"
        f"  [bold]WR vk:[/]            [dim]{wr_pk.hex()[:24]}…[/]\n"
        f"  [bold]threshold:[/]        [dim]{threshold} of {num_keypers}[/]\n",
        border_style="green",
        box=box.ROUNDED,
    ))


def start_services_tui(keyper_urls, host: str):
    """Start runtime services: keypers + vote proxy + WR oracle.

    Intended flow: c (chain) → e (publish election) → s (services) → d (DKG).
    """
    console.print()
    console.print(Rule("[bold magenta]Start runtime services[/]", style="magenta"))
    console.print()

    if _chain_state["anvil"] is None:
        console.print("[yellow]  Chain not running. Start it first (option c).[/]")
        return
    if not _chain_state["elections"]:
        console.print("[yellow]  No election published yet. Create one first (option e).[/]")
        return

    # Confirm up-front so no background server output interleaves with the prompt.
    election_addr = _chain_state["elections"][-1]
    if not Confirm.ask(
        f"  Start WR oracle + vote proxy + {len(keyper_urls)} keypers + tally daemon for election {election_addr[:10]}…?",
        default=True,
    ):
        console.print("  [dim]Cancelled.[/]")
        return

    # 1) WR oracle
    wr_port = 5300
    wr_url = f"http://127.0.0.1:{wr_port}"
    if "wr-oracle" not in _running_servers or not _running_servers["wr-oracle"]["thread"].is_alive():
        try:
            wr_app = create_wr_oracle_app(private_key=_chain_state["wr_sk"])
            wr_thread = threading.Thread(
                target=lambda a=wr_app: _run_flask_quiet(a, host="127.0.0.1", port=wr_port),
                daemon=True,
                name="wr-oracle",
            )
            wr_thread.start()
            _running_servers["wr-oracle"] = {"thread": wr_thread, "port": wr_port, "url": wr_url}
            console.print(f"  [green]✓[/] WR oracle starting [dim]({wr_url})[/]")
        except Exception as e:
            console.print(f"[red]  WR oracle launch failed: {e}[/]")
            return
    else:
        console.print(f"  [dim]WR oracle already running[/] [dim]({wr_url})[/]")

    # 2) Vote proxy (uses latest election as default)
    proxy_port = 5400
    proxy_url = f"http://{host}:{proxy_port}"
    if "vote-proxy" not in _running_servers or not _running_servers["vote-proxy"]["thread"].is_alive():
        try:
            proxy_app = create_vote_proxy_app(
                rpc_url=_chain_state["anvil"].rpc_url,
                private_key=_chain_state["proxy_key"],
                default_election_address=election_addr,
            )
            proxy_thread = threading.Thread(
                target=lambda a=proxy_app, h=host: _run_flask_quiet(a, host=h, port=proxy_port),
                daemon=True,
                name="vote-proxy",
            )
            proxy_thread.start()
            _running_servers["vote-proxy"] = {"thread": proxy_thread, "port": proxy_port, "url": proxy_url}
            console.print(f"  [green]✓[/] Vote proxy starting [dim]({proxy_url})[/] [dim]default election {election_addr[:10]}…[/]")
        except Exception as e:
            console.print(f"[red]  Vote proxy launch failed: {e}[/]")
            return
    else:
        console.print(f"  [dim]Vote proxy already running[/] [dim]({proxy_url})[/]")

    # 3) Keypers (chain credentials + signing keys configured)
    start_servers_tui(keyper_urls, keyper_host=host, confirm=False)

    # 4) Tally aggregator daemon (per-election for the demo)
    tally_label = "tally-daemon"
    if tally_label not in _running_servers or not _running_servers[tally_label]["thread"].is_alive():
        try:
            signer = Account.from_key(_chain_state["tally_key"])
            t = threading.Thread(
                target=lambda: tally_aggregator.daemon(
                    _chain_state["chain"],
                    election_addr,
                    signer,
                    poll=2.0,
                    quiet=True,
                ),
                daemon=True,
                name=tally_label,
            )
            t.start()
            _running_servers[tally_label] = {"thread": t, "port": None, "url": f"daemon:election:{election_addr}"}
            console.print(f"  [green]✓[/] Tally aggregator daemon started [dim](election {election_addr[:10]}…)[/]")
        except Exception as e:
            console.print(f"[red]  Tally daemon launch failed: {e}[/]")
    else:
        console.print("  [dim]Tally aggregator daemon already running[/]")


def create_election_on_chain_tui():
    """Wizard that calls ElectionRegistry.publishElection on demand."""
    console.print()
    console.print(Rule("[bold cyan]Create election on chain[/]", style="cyan"))
    console.print()

    if _chain_state["registry_addr"] is None:
        console.print("[yellow]  Chain not running. Start it first (option c).[/]")
        return

    num_candidates = IntPrompt.ask("  Number of candidates", default=3)
    while True:
        budget = IntPrompt.ask("  Budget (votes per ballot)", default=10)
        if budget >= 1:
            break
        console.print("[red]  Budget must be a positive integer.[/]")
    voting_window_hours = IntPrompt.ask("  Voting window (hours from now)", default=24)
    self_submit_fee = IntPrompt.ask("  Self-submit fee in wei (0 to disable)", default=0)

    now = int(time.time())
    voting_start = now - 60  # backdate by a minute so submitVote opens immediately
    voting_end = now + voting_window_hours * 3600

    pk_wr = _chain_state["wr_pk"]

    summary = Table(box=box.SIMPLE, border_style="cyan", show_header=False)
    summary.add_row("[bold]numCandidates[/]", str(num_candidates))
    summary.add_row("[bold]budget[/]", str(budget))
    summary.add_row("[bold]votingStart[/]", f"{voting_start}  [dim](now − 60s)[/]")
    summary.add_row("[bold]votingEnd[/]", f"{voting_end}  [dim](in {voting_window_hours}h)[/]")
    summary.add_row("[bold]selfSubmitFee[/]", f"{self_submit_fee} wei")
    summary.add_row("[bold]tallyAggregator[/]", _chain_state["tally_addr"])
    summary.add_row("[bold]voteProxy[/]", _chain_state["proxy_addr"])
    summary.add_row("[bold]keyperSet[/]", _chain_state["keyper_set_addr"])
    summary.add_row("[bold]pkWR[/]", pk_wr.hex()[:24] + "…")
    console.print(summary)

    if not Confirm.ask("  Publish?", default=True):
        console.print("  [dim]Cancelled.[/]")
        return

    try:
        election_addr = chain_setup.publish_election(
            chain=_chain_state["chain"],
            registry_address=_chain_state["registry_addr"],
            keyper_set_address=_chain_state["keyper_set_addr"],
            voting_start=voting_start,
            voting_end=voting_end,
            num_candidates=num_candidates,
            budget=budget,
            self_submit_fee=self_submit_fee,
            pk_wr=pk_wr,
            tally_aggregator=_chain_state["tally_addr"],
            vote_proxy=_chain_state["proxy_addr"],
        )
    except Exception as e:
        console.print(f"\n[red]publishElection failed: {e}[/]")
        return

    _chain_state["elections"].append(election_addr)
    _chain_state["candidate_names"] = []

    election = ElectionClient(_chain_state["chain"], election_addr)
    info = election.get_election()
    console.print(Panel(
        f"[bold green]  ✓ Election #{info['config']['electionId']} published[/]\n\n"
        f"  [bold]address:[/]       [dim]{election_addr}[/]\n"
        f"  [bold]numCandidates:[/] [dim]{info['config']['numCandidates']}[/]\n"
        f"  [bold]budget:[/]        [dim]{info['config']['budget']}[/]\n"
        f"  [bold]votingStart:[/]   [dim]{info['config']['votingStart']}[/]\n"
        f"  [bold]votingEnd:[/]     [dim]{info['config']['votingEnd']}[/]\n"
        f"  [bold]getPhase():[/]    [dim]{election.get_phase()}[/]\n",
        border_style="green",
        box=box.ROUNDED,
    ))


def enter_candidate_names_tui():
    """Prompt for human-readable candidate names for the latest election."""
    console.print()
    console.print(Rule("[bold cyan]Enter candidate names[/]", style="cyan"))
    console.print()

    if _chain_state["chain"] is None or not _chain_state["elections"]:
        console.print("[yellow]  Start chain (1) and publish an election (2) first.[/]")
        return

    election_addr = _chain_state["elections"][-1]
    election = ElectionClient(_chain_state["chain"], election_addr)
    info = election.get_election()
    num_cand = int(info["config"]["numCandidates"])

    existing = _chain_state.get("candidate_names") or []
    names: list[str] = []
    for j in range(num_cand):
        default = existing[j] if j < len(existing) else f"Candidate {j}"
        name = Prompt.ask(f"  Candidate {j} name", default=default).strip()
        if not name:
            name = f"Candidate {j}"
        names.append(name)

    _chain_state["candidate_names"] = names

    tbl = Table(box=box.ROUNDED, border_style="cyan", title="[bold]Candidate names[/]")
    tbl.add_column("index", style="bold cyan")
    tbl.add_column("name", style="white")
    for j, name in enumerate(names):
        tbl.add_row(str(j), name)
    console.print(tbl)


def stop_chain_tui():
    """Tear down anvil and clear chain state."""
    console.print()
    console.print(Rule("[bold yellow]Stop chain[/]", style="yellow"))

    if _chain_state["anvil"] is None:
        console.print("[yellow]  Chain is not running.[/]")
        return

    chain_setup.stop_anvil(_chain_state["anvil"])
    for k in list(_chain_state.keys()):
        _chain_state[k] = [] if isinstance(_chain_state[k], list) else None
    console.print("[dim]  anvil terminated; chain state cleared.[/]")


def vote_tui(host: str):
    """Submit votes via the dev vote proxy (uses WR oracle for attestations)."""
    console.print()
    console.print(Rule("[bold green]Cast votes[/]", style="green"))
    console.print()

    if _chain_state["anvil"] is None or not _chain_state["elections"]:
        console.print("[yellow]  Start chain (c) and publish an election (e) first.[/]")
        return

    election_addr = _chain_state["elections"][-1]
    election = ElectionClient(_chain_state["chain"], election_addr)
    info = election.get_election()
    num_cand = int(info["config"]["numCandidates"])
    budget = int(info["config"]["budget"])

    proxy_url = f"http://{host}:5400"
    wr_url = "http://127.0.0.1:5300"
    rpc_url = _chain_state["anvil"].rpc_url

    stored = _chain_state.get("candidate_names") or []
    candidate_names = [
        stored[j] if j < len(stored) else f"Candidate {j}"
        for j in range(num_cand)
    ]

    cand_tbl = Table(box=box.SIMPLE, border_style="green",
                     title="[bold]Candidates[/]", title_style="bold green")
    cand_tbl.add_column("index", style="bold cyan")
    cand_tbl.add_column("name", style="white")
    for j, name in enumerate(candidate_names):
        cand_tbl.add_row(str(j), name)

    console.print(Panel(
        f"[bold]Election:[/] [dim]{election_addr}[/]\n"
        f"[bold]Candidates:[/] {num_cand}   [bold]Budget:[/] {budget}\n"
        f"[bold]Vote proxy:[/] [dim]{proxy_url}[/]\n"
        f"[bold]WR oracle:[/] [dim]{wr_url}[/]\n"
        f"[dim]Each ballot is a vector of {num_cand} non-negative ints summing to {budget}.[/]",
        border_style="green",
        box=box.ROUNDED,
    ))
    console.print(cand_tbl)

    n_voters = IntPrompt.ask("  How many voters?", default=1)
    if n_voters <= 0:
        console.print("[dim]Cancelled.[/]")
        return

    default_vec = [budget] + [0] * (num_cand - 1)
    default_str = " ".join(str(v) for v in default_vec)

    ok = 0
    for v_idx in range(1, n_voters + 1):
        console.print()
        console.print(Rule(f"[bold]Voter {v_idx}/{n_voters}[/]", style="green"))
        console.print(cand_tbl)
        while True:
            line = Prompt.ask(
                f"  Voter {v_idx} ballot — {num_cand} ints summing to {budget} "
                f"(space- or comma-separated)",
                default=default_str,
            ).strip()
            tokens = line.replace(",", " ").split()
            try:
                vec = [int(x) for x in tokens]
            except ValueError:
                console.print("[red]  Invalid input: expected integers.[/]")
                continue
            if len(vec) != num_cand:
                console.print(f"[red]  Expected {num_cand} values, got {len(vec)}.[/]")
                continue
            if any(v < 0 or v > budget for v in vec):
                console.print(f"[red]  Each value must be in [0, {budget}].[/]")
                continue
            if sum(vec) != budget:
                console.print(f"[red]  Vector must sum to {budget}, got {sum(vec)}.[/]")
                continue
            break

        breakdown = ", ".join(
            f"{candidate_names[j]}={vec[j]}" for j in range(num_cand) if vec[j] > 0
        ) or "(empty)"
        console.print(f"  [dim]Submitting Voter {v_idx} ballot: {breakdown}…[/]")
        if voter.cast_vote_via_proxy(
            proxy_url,
            rpc_url,
            election_addr,
            vec,
            wr_url=wr_url,
        ):
            ok += 1

    console.print(Panel(
        f"[bold green]✓ Submitted {ok}/{n_voters} ballots[/]",
        border_style="green",
        box=box.ROUNDED,
    ))


def fast_forward_to_voting_end_tui():
    """Advance anvil time to >= votingEnd+1 for the current election."""
    console.print()
    console.print(Rule("[bold yellow]Fast-forward to voting end[/]", style="yellow"))
    console.print()

    if _chain_state["chain"] is None or not _chain_state["elections"]:
        console.print("[yellow]  Start chain (c) and publish an election (e) first.[/]")
        return

    election_addr = _chain_state["elections"][-1]
    election = ElectionClient(_chain_state["chain"], election_addr)
    info = election.get_election()
    ve = int(info["config"]["votingEnd"])

    now = int(_chain_state["chain"].w3.eth.get_block("latest")["timestamp"])
    target = ve + 1
    if target <= now:
        target = now + 1

    if not Confirm.ask(
        f"  Set next block timestamp to {target} (now={now}, votingEnd={ve}) and mine 1 block?",
        default=True,
    ):
        console.print("  [dim]Cancelled.[/]")
        return

    # Call anvil RPC directly through the connected provider.
    prov = _chain_state["chain"].w3.provider
    res1 = prov.make_request("anvil_setNextBlockTimestamp", [target])
    if res1.get("error"):
        console.print(f"[red]  anvil_setNextBlockTimestamp failed: {res1['error']}[/]")
        return
    res2 = prov.make_request("anvil_mine", [1])
    if res2.get("error"):
        console.print(f"[red]  anvil_mine failed: {res2['error']}[/]")
        return

    now2 = int(_chain_state["chain"].w3.eth.get_block("latest")["timestamp"])
    console.print(Panel(
        f"[bold green]✓ Time advanced[/]\n\n"
        f"[bold]Election:[/] [dim]{election_addr}[/]\n"
        f"[bold]timestamp:[/] {now} → {now2}\n"
        f"[bold]votingEnd:[/] {ve}",
        border_style="green",
        box=box.ROUNDED,
    ))


def submit_decryption_shares_tui(keyper_urls: list[str]):
    """Trigger each keyper to compute + submit its decryption share on-chain."""
    console.print()
    console.print(Rule("[bold green]Submit decryption shares[/]", style="green"))
    console.print()

    if _chain_state["anvil"] is None or not _chain_state["elections"]:
        console.print("[yellow]  Start chain (c) and publish an election (e) first.[/]")
        return

    election_addr = _chain_state["elections"][-1]
    if not Confirm.ask(
        f"  Ask {len(keyper_urls)} keypers to submit shares for election {election_addr[:10]}…?",
        default=True,
    ):
        console.print("  [dim]Cancelled.[/]")
        return

    ok = 0
    for i, url in enumerate(keyper_urls, start=1):
        try:
            r = requests.post(
                f"{url.rstrip('/')}/decrypt/publish_on_chain",
                json={"election_address": election_addr},
                timeout=120,
            )
            body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {"text": r.text}
        except Exception as e:
            console.print(f"  [red]✗[/] Keyper {i} {url}: {e}")
            continue

        if r.status_code == 200 and "error" not in body:
            ok += 1
            skipped = body.get("skipped")
            if skipped:
                console.print(f"  [dim]·[/] Keyper {i}: {skipped}")
            else:
                txh = str(body.get("tx_hash", ""))[:14]
                console.print(f"  [green]✓[/] Keyper {i}: submitted (tx {txh}…)")
        else:
            console.print(f"  [red]✗[/] Keyper {i}: {body.get('error', f'HTTP {r.status_code}')}")

    console.print(Panel(
        f"[bold green]✓ Decryption share submissions triggered: {ok}/{len(keyper_urls)}[/]",
        border_style="green",
        box=box.ROUNDED,
    ))


def show_result_tui():
    console.print()
    console.print(Rule("[bold cyan]Election result (on-chain)[/]", style="cyan"))
    console.print()

    if _chain_state["anvil"] is None or not _chain_state["elections"]:
        console.print("[yellow]  Start chain (c) and publish an election (e) first.[/]")
        return

    election_addr = _chain_state["elections"][-1]
    election = ElectionClient(_chain_state["chain"], election_addr)
    if not election.is_result_finalized():
        console.print("[yellow]  Result not finalized yet.[/]")
        return

    res = election.get_result()
    console.print(Panel(
        f"[bold]Election:[/] [dim]{election_addr}[/]\n"
        f"[bold]Tally:[/] {res['tally']}\n"
        f"[bold]Keyper indices used:[/] {res['keyperIndices']}",
        border_style="cyan",
        box=box.ROUNDED,
    ))


def show_aggregate_tui():
    console.print()
    console.print(Rule("[bold cyan]Election aggregate (on-chain)[/]", style="cyan"))
    console.print()

    if _chain_state["anvil"] is None or not _chain_state["elections"]:
        console.print("[yellow]  Start chain (1) and publish an election (2) first.[/]")
        return

    election_addr = _chain_state["elections"][-1]
    election = ElectionClient(_chain_state["chain"], election_addr)
    try:
        agg = election.get_aggregate()
    except Exception as e:
        console.print(f"[yellow]  Aggregate not published yet.[/]\n  [dim]{e}[/]")
        return

    # Keep this readable: show per-candidate ciphertext fingerprints.
    rows = []
    for j, (c1, c2) in enumerate(agg["aggregates"]):
        rows.append((j, c1.hex()[:16] + "…", c2.hex()[:16] + "…"))

    tbl = Table(box=box.SIMPLE, border_style="cyan")
    tbl.add_column("cand", style="bold")
    tbl.add_column("C1 (g2)", style="dim")
    tbl.add_column("C2 (g2)", style="dim")
    for j, c1fp, c2fp in rows:
        tbl.add_row(str(j), c1fp, c2fp)

    from rich.console import Group
    from rich.text import Text as RichText
    console.print(Panel(
        Group(
            RichText.from_markup(f"[bold]Election:[/] [dim]{election_addr}[/]"),
            RichText.from_markup(""),
            tbl,
        ),
        border_style="cyan",
        box=box.ROUNDED,
    ))


def main_menu(keyper_urls, host):
    """Main interactive menu loop."""
    while True:
        # Show running server count in header
        alive = sum(1 for s in _running_servers.values() if s["thread"].is_alive())
        server_indicator = f"  [dim green]● {alive} servers running[/]" if alive else "  [dim red]● No servers running[/]"
        if _chain_state["anvil"] is not None:
            n_elec = len(_chain_state["elections"])
            chain_indicator = (
                f"  [dim green]● chain up — KeyperSet={_chain_state['keyper_set_addr'][:10]}…  "
                f"Registry={_chain_state['registry_addr'][:10]}…  "
                f"elections={n_elec}[/]"
            )
        else:
            chain_indicator = "  [dim]● chain not running[/]"

        console.print()
        console.print(Rule("[bold magenta]Admin Menu[/]", style="dim"))
        console.print(server_indicator)
        console.print(chain_indicator)
        console.print()
        console.print("  [bold cyan]1[/]  Start chain (anvil + KeyperSet + Registry)")
        console.print("  [bold cyan]2[/]  Create election on chain (publishElection)")
        console.print("  [bold cyan]3[/]  Enter candidate names")
        console.print("  [bold green]4[/]  Start services (keypers + vote proxy + WR oracle + Tally Aggregator)")
        console.print("  [bold cyan]5[/]  Run DKG coordinator (incl. publish on-chain)")
        console.print("  [bold green]6[/]  Cast votes (via vote proxy)")
        console.print("  [bold yellow]7[/]  Fast-forward time to votingEnd")
        console.print("  [bold cyan]8[/]  Show aggregate (on-chain)")
        console.print("  [bold green]9[/]  Keypers submit decryption shares (on-chain)")
        console.print("  [bold cyan]0[/]  Show result (on-chain)")
        console.print("  [bold yellow]s[/]  Stop chain")
        console.print("  [bold magenta]q[/]  Quit")
        console.print()

        choice = Prompt.ask(
            "[bold]Select[/]",
            choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "s", "q"],
            default="1",
        )

        try:
            if choice == "1":
                start_chain_tui(num_keypers=len(keyper_urls), threshold=max(1, len(keyper_urls) - 1), anvil_port=8545)
            elif choice == "2":
                create_election_on_chain_tui()
            elif choice == "3":
                enter_candidate_names_tui()
            elif choice == "4":
                start_services_tui(keyper_urls, host=host)
            elif choice == "5":
                run_dkg_tui(keyper_urls)
            elif choice == "6":
                vote_tui(host)
            elif choice == "7":
                fast_forward_to_voting_end_tui()
            elif choice == "8":
                show_aggregate_tui()
            elif choice == "9":
                submit_decryption_shares_tui(keyper_urls)
            elif choice == "0":
                show_result_tui()
            elif choice == "s":
                stop_chain_tui()
            elif choice == "q":
                if _chain_state["anvil"] is not None:
                    console.print("\n[dim]Stopping anvil…[/]")
                    chain_setup.stop_anvil(_chain_state["anvil"])
                if alive:
                    console.print(f"\n[dim]Shutting down {alive} daemon server(s)…[/]")
                console.print("[dim]Goodbye.[/]")
                break
        except KeyboardInterrupt:
            console.print("\n[dim]Interrupted.[/]")
        except Exception as e:
            console.print(f"\n[red]Error: {e}[/]")


def main():
    parser = argparse.ArgumentParser(
        description="Election Admin TUI",
        epilog="Example: python admin_tui.py --num-keypers 3",
    )
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

    if args.keyper_urls:
        keyper_urls = [u.strip() for u in args.keyper_urls.split(",")]
    else:
        keyper_urls = [
            f"http://{host}:{args.keyper_base_port + i}"
            for i in range(args.num_keypers)
        ]

    console.print(BANNER)
    console.print(Align.center(f"[dim]Keypers: {len(keyper_urls)}[/]"))

    main_menu(keyper_urls, host)


if __name__ == "__main__":
    main()
