"""
CyberSentinel — N8N Workflow Activator
=======================================
Ensures all 5 workflows are active, published, and have correct history entries.
Run this any time after n8n starts fresh or after re-importing workflows.

Usage:
    python scripts/activate_n8n_workflows.py
    python scripts/activate_n8n_workflows.py --db D:/N8N/database.sqlite
    python scripts/activate_n8n_workflows.py --workflows-dir n8n/workflows
"""

import sqlite3
import json
import uuid
import datetime
import argparse
import sys
import os
import time

WORKFLOWS_DIR = os.path.join(os.path.dirname(__file__), '..', 'n8n', 'workflows')
N8N_DB_PATH   = 'D:/N8N/database.sqlite'

WORKFLOW_FILES = {
    'wf01-critical-alert-soar':  '01_critical_alert_soar.json',
    'wf02-daily-soc-report':     '02_daily_soc_report.json',
    'wf03-cve-intel-pipeline':   '03_cve_intel_pipeline.json',
    'wf04-sla-watchdog':         '04_sla_watchdog.json',
    'wf05-weekly-board-report':  '05_weekly_board_report.json',
}


def load_workflow(workflows_dir, filename):
    path = os.path.join(workflows_dir, filename)
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def activate_workflows(db_path, workflows_dir, dry_run=False):
    print(f"[n8n activator] DB: {db_path}")
    print(f"[n8n activator] Workflows dir: {workflows_dir}")

    if not os.path.exists(db_path):
        print(f"[ERROR] SQLite DB not found at {db_path}")
        print("  -> Make sure N8N has started at least once (it creates the DB on first run)")
        sys.exit(1)

    conn = sqlite3.connect(db_path)
    cur  = conn.cursor()
    now  = datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%d %H:%M:%S')

    # Check which workflows exist in DB
    cur.execute('SELECT id, active, versionId, activeVersionId FROM workflow_entity')
    existing = {r[0]: {'active': r[1], 'versionId': r[2], 'activeVersionId': r[3]}
                for r in cur.fetchall()}

    print(f"\n[n8n activator] Found {len(existing)} workflows in DB")
    needs_import  = []
    needs_fix     = []

    for wf_id, fname in WORKFLOW_FILES.items():
        if wf_id not in existing:
            needs_import.append(wf_id)
            print(f"  [X] MISSING {wf_id}")
        else:
            row = existing[wf_id]
            issues = []
            if not row['active']:
                issues.append('inactive')
            if not row['activeVersionId']:
                issues.append('no activeVersionId')

            cur.execute('SELECT workflowId FROM workflow_published_version WHERE workflowId=?', (wf_id,))
            if cur.fetchone() is None:
                issues.append('not published')

            if issues:
                needs_fix.append(wf_id)
                print(f"  [!] NEEDS FIX {wf_id} ({', '.join(issues)})")
            else:
                print(f"  [OK]          {wf_id}")

    if not needs_import and not needs_fix:
        print("\n[n8n activator] All workflows are already active and published. Nothing to do.")
        conn.close()
        return

    if dry_run:
        print("\n[n8n activator] DRY RUN — no changes made.")
        conn.close()
        return

    # Fix each workflow that needs attention
    for wf_id in needs_fix:
        fname = WORKFLOW_FILES[wf_id]
        try:
            wf = load_workflow(workflows_dir, fname)
        except FileNotFoundError:
            print(f"  [WARN] Workflow file not found: {fname} — skipping history update")
            wf = None

        row = existing[wf_id]
        vid = row['versionId']

        # If we have the file, check if history entry matches
        if wf:
            nodes_json       = json.dumps(wf['nodes'])
            connections_json = json.dumps(wf['connections'])

            cur.execute('SELECT nodes FROM workflow_history WHERE versionId=?', (vid,))
            hist_row = cur.fetchone()

            if hist_row is None or json.loads(hist_row[0]) != wf['nodes']:
                # Insert a new history version with the correct nodes
                new_vid = str(uuid.uuid4())
                cur.execute(
                    '''INSERT INTO workflow_history
                       (versionId, workflowId, authors, createdAt, updatedAt, nodes, connections, name, autosaved, description)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (new_vid, wf_id, 'admin', now, now, nodes_json, connections_json, wf['name'], 0, '')
                )
                cur.execute(
                    'UPDATE workflow_entity SET versionId=?, activeVersionId=?, nodes=?, active=1 WHERE id=?',
                    (new_vid, new_vid, nodes_json, wf_id)
                )
                vid = new_vid
                print(f"  -> {wf_id}: updated history + versionId -> {new_vid[:12]}")
            else:
                # History is correct, just fix active + activeVersionId
                cur.execute(
                    'UPDATE workflow_entity SET active=1, activeVersionId=? WHERE id=?',
                    (vid, wf_id)
                )
                print(f"  -> {wf_id}: set active=1, activeVersionId={vid[:12]}")
        else:
            # No file — just activate and point to existing versionId
            cur.execute(
                'UPDATE workflow_entity SET active=1, activeVersionId=? WHERE id=?',
                (vid, wf_id)
            )
            print(f"  -> {wf_id}: set active=1 (no file, kept existing version)")

        # Upsert workflow_published_version
        cur.execute('SELECT workflowId FROM workflow_published_version WHERE workflowId=?', (wf_id,))
        if cur.fetchone() is None:
            cur.execute(
                'INSERT INTO workflow_published_version (workflowId, publishedVersionId, createdAt, updatedAt) VALUES (?,?,?,?)',
                (wf_id, vid, now, now)
            )
        else:
            cur.execute(
                'UPDATE workflow_published_version SET publishedVersionId=?, updatedAt=? WHERE workflowId=?',
                (vid, now, wf_id)
            )
        print(f"  -> {wf_id}: published_version -> {vid[:12]}")

    # Handle completely missing workflows (needs full import via n8n CLI, just warn)
    for wf_id in needs_import:
        fname = WORKFLOW_FILES[wf_id]
        print(f"\n  [WARN] {wf_id} is not in DB at all.")
        print(f"  -> Import it first: docker exec N8N n8n import:workflow --input=/home/node/workflows/{fname}")

    conn.commit()
    conn.close()
    print(f"\n[n8n activator] Done. Restart N8N for changes to take effect:")
    print("  docker restart N8N")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Activate and publish n8n workflows in CyberSentinel')
    parser.add_argument('--db',            default=N8N_DB_PATH,   help='Path to n8n database.sqlite')
    parser.add_argument('--workflows-dir', default=WORKFLOWS_DIR, help='Path to workflow JSON files')
    parser.add_argument('--dry-run',       action='store_true',   help='Show what would change without modifying DB')
    parser.add_argument('--wait',          type=int, default=0,   help='Wait N seconds before running (for startup scripts)')
    args = parser.parse_args()

    if args.wait:
        print(f"[n8n activator] Waiting {args.wait}s for n8n to initialize...")
        time.sleep(args.wait)

    activate_workflows(
        db_path=os.path.abspath(args.db),
        workflows_dir=os.path.abspath(args.workflows_dir),
        dry_run=args.dry_run,
    )
