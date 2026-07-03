#!/usr/bin/env python3
"""Scansiona con nmap (OS + servizi) gli IP di un file di input e registra
i risultati (tipo dispositivo, OS, servizi) in un database SQLite.

Uso tipico:
    python scan_and_store.py --input up_ips.txt --db instance/inventory.db
"""

import argparse
import tempfile
from pathlib import Path

import scan_pipeline
import scanner_db


def read_ips(path):
    ips = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            ips.append(line)
    return ips


def chunk(items, size):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def build_command(ip_list_file, xml_out, args):
    """Ritorna gli argomenti nmap SENZA il nome del binario: sia
    nmap_proxy_client in modalità nativa (che lo aggiunge da sé) sia in
    modalità proxy (dove il binario è risolto sull'host remoto) si
    aspettano solo gli argomenti."""
    cmd = [
        "-sV", "-Pn",
        "-T" + args.timing,
        "--top-ports", str(args.top_ports),
        "--host-timeout", args.host_timeout,
        "-oX", str(xml_out),
    ]
    if not args.no_os:
        cmd += ["-O", "--osscan-guess"]
    if not args.no_scripts:
        cmd.append("-sC")
    cmd += ["-iL", str(ip_list_file)]
    return cmd


def run_batch(batch_ips, batch_idx, args, conn):
    scans_dir = Path(args.scans_dir)
    scans_dir.mkdir(parents=True, exist_ok=True)

    ts = scan_pipeline.now_iso().replace(":", "-")
    xml_out = scans_dir / f"batch_{batch_idx:04d}_{ts}.xml"

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8"
    ) as f:
        f.write("\n".join(batch_ips))
        ip_list_file = Path(f.name)

    cmd = build_command(ip_list_file, xml_out, args)
    print(f"[batch {batch_idx}] {len(batch_ips)} host -> {xml_out.name}")

    try:
        result = scan_pipeline.run_and_store(cmd, xml_out, conn, len(batch_ips), timeout=args.batch_timeout)
    finally:
        ip_list_file.unlink(missing_ok=True)

    if result["status"] == "timeout":
        print(f"[batch {batch_idx}] timeout dopo {args.batch_timeout}s, "
              f"uso i risultati parziali scritti finora")

    print(f"[batch {batch_idx}] completato: {len(result['hosts_up'])}/{len(batch_ips)} host registrati "
          f"({result['status']})")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="up_ips.txt", help="File con un IP per riga")
    parser.add_argument(
        "--db", default=scanner_db.resolve_db_target(Path(__file__).parent / "instance" / "inventory.db"),
        help="Percorso database SQLite, oppure URL postgresql://... (default: DATABASE_URL se impostata)",
    )
    parser.add_argument("--scans-dir", default="scans", help="Cartella per gli XML grezzi")
    parser.add_argument("--batch-size", type=int, default=32, help="Host per batch nmap")
    parser.add_argument("--top-ports", type=int, default=200, help="Numero porte da scansionare")
    parser.add_argument("--timing", default="4", choices=["1", "2", "3", "4", "5"],
                         help="Timing template nmap (-T)")
    parser.add_argument("--host-timeout", default="180s",
                         help="--host-timeout nmap per host (90s era troppo aggressivo su reti "
                              "con molti hop/filtri: causava host 'timed_out' con OS/servizi vuoti "
                              "per la maggioranza degli host)")
    parser.add_argument("--batch-timeout", type=int, default=1800,
                         help="Timeout (s) del processo nmap per l'intero batch")
    parser.add_argument("--no-os", action="store_true", help="Disabilita OS detection (-O)")
    parser.add_argument("--no-scripts", action="store_true",
                         help="Disabilita gli script NSE default (-sC): per default sono attivi "
                              "e il loro output viene salvato per servizio (service_scripts)")
    parser.add_argument("--limit", type=int, help="Scansiona solo i primi N IP (per test)")
    parser.add_argument("--resume", action="store_true",
                         help="Salta gli IP già presenti nel DB")
    args = parser.parse_args()

    ips = read_ips(args.input)
    if args.limit:
        ips = ips[:args.limit]

    conn = scanner_db.connect(args.db)
    scanner_db.init_db(conn)

    if args.resume:
        already = scanner_db.get_scanned_ips(conn)
        before = len(ips)
        ips = [ip for ip in ips if ip not in already]
        print(f"--resume: {before - len(ips)} IP già presenti nel DB, saltati")

    if not ips:
        print("Nessun IP da scansionare.")
        return

    batches = list(chunk(ips, args.batch_size))
    print(f"Totale IP: {len(ips)} | Batch: {len(batches)} da {args.batch_size} host")

    for idx, batch_ips in enumerate(batches, start=1):
        run_batch(batch_ips, idx, args, conn)

    conn.close()
    print("Scansione completata.")


if __name__ == "__main__":
    main()
