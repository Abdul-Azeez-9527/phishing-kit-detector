"""
report.py
Builds a human-readable summary of discovered phishing-kit clusters and
a networkx graph image showing which domains share the same kit.

Run:
    python src/report.py
"""

import os
import networkx as nx
import matplotlib
matplotlib.use("Agg")  # headless - no display needed, light on resources
import matplotlib.pyplot as plt
import db

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "output")


def generate():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    conn = db.get_conn()
    cur = conn.cursor()
    cur.execute(
        """SELECT c.cluster_label, f.id as fingerprint_id, f.title,
                  f.num_forms, f.num_password_fields, f.suspicious_js_flags,
                  p.final_url, u.domain, u.source
           FROM cluster_members cm
           JOIN clusters c ON cm.cluster_id = c.id
           JOIN fingerprints f ON cm.fingerprint_id = f.id
           JOIN pages p ON f.page_id = p.id
           JOIN urls u ON p.url_id = u.id
           ORDER BY c.cluster_label"""
    )
    rows = cur.fetchall()
    conn.close()

    if not rows:
        print("[!] No clusters found yet. Run the pipeline first.")
        return

    # --- Text report ---
    report_path = os.path.join(OUTPUT_DIR, "cluster_report.md")
    clusters = {}
    for row in rows:
        clusters.setdefault(row["cluster_label"], []).append(row)

    with open(report_path, "w") as f:
        f.write("# Phishing Kit Cluster Report\n\n")
        f.write(f"Total clusters found: {len(clusters)}\n\n")
        for label, members in clusters.items():
            f.write(f"## Cluster {label} ({len(members)} pages)\n\n")
            domains = sorted({m["domain"] for m in members if m["domain"]})
            f.write(f"- Domains involved: {', '.join(domains)}\n")
            titles = sorted({m["title"] for m in members if m["title"]})
            f.write(f"- Page titles seen: {', '.join(titles[:10])}\n")
            flags = sorted({
                flag for m in members if m["suspicious_js_flags"]
                for flag in m["suspicious_js_flags"].split(",") if flag
            })
            if flags:
                f.write(f"- Suspicious JS patterns: {', '.join(flags)}\n")
            avg_forms = sum(m["num_forms"] for m in members) / len(members)
            avg_pw = sum(m["num_password_fields"] for m in members) / len(members)
            f.write(f"- Avg forms per page: {avg_forms:.1f}, "
                    f"avg password fields: {avg_pw:.1f}\n\n")

    print(f"[+] Text report saved to {report_path}")

    # --- Graph image: domains connected if they share a cluster ---
    g = nx.Graph()
    for label, members in clusters.items():
        domains = {m["domain"] for m in members if m["domain"]}
        g.add_nodes_from(domains)
        domains = list(domains)
        for i in range(len(domains)):
            for j in range(i + 1, len(domains)):
                g.add_edge(domains[i], domains[j], cluster=label)

    if g.number_of_nodes() > 0:
        plt.figure(figsize=(10, 8))
        pos = nx.spring_layout(g, seed=42, k=0.5)
        nx.draw_networkx_nodes(g, pos, node_size=300, node_color="#e74c3c")
        nx.draw_networkx_edges(g, pos, alpha=0.4)
        nx.draw_networkx_labels(g, pos, font_size=7)
        plt.title("Phishing domains sharing the same kit (connected = same cluster)")
        plt.axis("off")
        graph_path = os.path.join(OUTPUT_DIR, "cluster_graph.png")
        plt.savefig(graph_path, dpi=150, bbox_inches="tight")
        plt.close()
        print(f"[+] Graph image saved to {graph_path}")
    else:
        print("[!] No domain relationships to graph.")


if __name__ == "__main__":
    generate()
