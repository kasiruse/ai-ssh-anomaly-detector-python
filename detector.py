# ==========================================================
# Application: AI Log Anomaly Detector (systemd Edition)
# Author: kasiruse
# Description: Analyzes SSH login behaviors directly from journalctl
#              using Machine Learning (Isolation Forest) to detect
#              Brute Force attacks and anomalous IP activities.
# ==========================================================

import argparse
import subprocess
import re
import pandas as pd
from sklearn.ensemble import IsolationForest
from collections import defaultdict

def fetch_cachyos_logs(days_back=2):
    """
    Runs the journalctl command to fetch SSH logs for the specified number of days.
    """
    print(f"[INFO] Fetching SSH logs directly from systemd journal (last {days_back} days)...")

    try:
        # Run: journalctl -u sshd --since "X days ago" --no-pager
        result = subprocess.run(
            ['journalctl', '-u', 'sshd', '--since', f'{days_back} days ago', '--no-pager'],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.splitlines()

    except FileNotFoundError:
        print("[ERROR] 'journalctl' command not found. Are you sure you are on a systemd Linux?")
        return []
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to read journalctl. Try running script with 'sudo'.\nDetails: {e}")
        return []

def parse_and_aggregate_logs(log_lines):
    """
    Extracts IPs and aggregates their behavior from the raw journalctl output.
    """
    if not log_lines:
        return None

    # Regex pattern to match SSH login attempts
    ssh_pattern = re.compile(r"(?P<action>Failed|Accepted).*?from (?P<ip>\S+)")
    ip_behavior = defaultdict(lambda: {'failed_count': 0, 'success_count': 0})

    for line in log_lines:
        match = ssh_pattern.search(line)
        if match:
            action = match.group('action')
            ip = match.group('ip')

            if action == "Failed":
                ip_behavior[ip]['failed_count'] += 1
            elif action == "Accepted":
                ip_behavior[ip]['success_count'] += 1

    dataset = []
    for ip, stats in ip_behavior.items():
        total_attempts = stats['failed_count'] + stats['success_count']
        failure_rate = stats['failed_count'] / total_attempts if total_attempts > 0 else 0

        dataset.append({
            'IP_Address': ip,
            'Total_Attempts': total_attempts,
            'Failed_Attempts': stats['failed_count'],
            'Failure_Rate': failure_rate
        })

    return pd.DataFrame(dataset)

def detect_anomalies(df, contamination_level=0.05):
    """
    Applies the Isolation Forest ML model to detect abnormal IP behavior.
    """
    if df is None or df.empty:
        print("[INFO] No SSH login data found to analyze.")
        return

    print(f"[INFO] Analyzed {len(df)} unique IP addresses. Running AI model...")
    features = df[['Total_Attempts', 'Failed_Attempts', 'Failure_Rate']]

    # Initialize and train the AI Model
    model = IsolationForest(contamination=contamination_level, random_state=42)
    model.fit(features)

    # Predict (-1 means anomaly, 1 means normal)
    df['Is_Anomaly'] = model.predict(features)
    anomalies = df[df['Is_Anomaly'] == -1]

    # Print Report
    print("\n" + "="*50)
    print("       AI REPORT")
    print("="*50)

    if anomalies.empty:
        print("No anomalies detected. System seems secure.")
    else:
        for index, row in anomalies.iterrows():
            print(f"!!! SUSPICIOUS IP DETECTED: {row['IP_Address']:<15}")
            print(f"   -> Total Attempts : {row['Total_Attempts']}")
            print(f"   -> Failed Attempts: {row['Failed_Attempts']}")
            print(f"   -> Failure Rate   : {row['Failure_Rate']*100:.1f}%\n")

# ---------------------------------------------------------
# MAIN EXECUTION & CLI ARGUMENTS
# ---------------------------------------------------------
if __name__ == "__main__":
    # Setup Argument Parser for professional CLI usage
    parser = argparse.ArgumentParser(description="AI-Powered SSH Log Anomaly Detector")
    parser.add_argument(
        "-d", "--days",
        type=int,
        default=2,
        help="Number of days to scan back in journalctl (default: 2)"
    )
    parser.add_argument(
        "-c", "--contamination",
        type=float,
        default=0.05,
        help="Expected percentage of malicious IPs for the AI model (default: 0.05)"
    )

    args = parser.parse_args()

    # Run the pipeline with user arguments
    raw_log_lines = fetch_cachyos_logs(days_back=args.days)
    behavior_df = parse_and_aggregate_logs(raw_log_lines)
    detect_anomalies(behavior_df, contamination_level=args.contamination)
