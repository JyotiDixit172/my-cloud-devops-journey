#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AWS Auditor — high-risk misconfiguration scanner
Author: You (with ChatGPT)
Python: 3.9+

What it does
------------
Calls AWS APIs (boto3) to find common, high-impact risks and writes:
  - JSON report:  aws_audit_report.json
  - CSV  report:  aws_audit_report.csv

Scopes (initial set; extendable)
--------------------------------
EC2 Security Groups:
  - Ingress from 0.0.0.0/0 on sensitive ports (22, 3389, all ports)
  - Egress wide open to 0.0.0.0/0 on all ports

S3:
  - Public buckets (ACL or policy-based)
  - No default encryption

IAM:
  - Users without MFA
  - Root account: MFA not enabled / access keys present
  - Access keys unused > 90 days
  - Weak/absent account password policy

CloudTrail:
  - No org/multi-region trail (visibility risk)

EBS (account-level):
  - Default EBS encryption disabled

EC2 Instances:
  - IMDSv2 not enforced

RDS:
  - Publicly accessible DB instances

ECR:
  - Image scan on push disabled

GuardDuty:
  - Not enabled (per region)

KMS:
  - Customer-managed keys with rotation disabled

Report fields
-------------
account_id, region, service, check_id, severity, status, resource_id,
description, remediation, reference

Usage
-----
$ pip install -r requirements.txt
$ export AWS_PROFILE=yourprofile   # or configure default credentials
$ python aws_audit.py              # audits all commercial regions by default

Notes
-----
- Requires IAM perms for: ec2, s3, iam, sts, cloudtrail, ecr, rds, guardduty, kms, elasticfilesystem (optional), kms, etc.
- Reads regions from EC2's describe_regions; you can override with --regions.
"""

import argparse
import csv
import json
import sys
from datetime import datetime, timezone, timedelta

import boto3
from botocore.config import Config
from dateutil.parser import parse as dt_parse

SENSITIVE_PORTS = {22, 3389}  # SSH, RDP
DEFAULT_UNUSED_KEY_AGE_DAYS = 90

# ---------- helpers ----------

def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()

def add_finding(findings, account_id, region, service, check_id, severity,
                status, resource_id, description, remediation, reference):
    findings.append({
        "timestamp": utc_now_iso(),
        "account_id": account_id,
        "region": region,
        "service": service,
        "check_id": check_id,
        "severity": severity,           # CRITICAL | HIGH | MEDIUM | LOW | INFO
        "status": status,               # FAIL | WARN | PASS | INFO
        "resource_id": resource_id,
        "description": description,
        "remediation": remediation,
        "reference": reference
    })

def write_reports(findings, out_json="aws_audit_report.json", out_csv="aws_audit_report.csv"):
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)
    # CSV (flatten keys)
    if findings:
        keys = list(findings[0].keys())
        with open(out_csv, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            for row in findings:
                w.writerow(row)

def get_all_regions(session):
    ec2 = session.client("ec2", config=Config(retries={"max_attempts": 10, "mode": "standard"}))
    resp = ec2.describe_regions(AllRegions=False)
    return [r["RegionName"] for r in resp.get("Regions", [])]

def get_account_id(session):
    sts = session.client("sts")
    return sts.get_caller_identity()["Account"]

def safe_get(dct, *keys, default=None):
    cur = dct
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return cur

# ---------- checks (each returns list of findings) ----------

def check_sg_ingress_open(session, account_id, region):
    findings = []
    ec2 = session.client("ec2", region_name=region)
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page.get("SecurityGroups", []):
            sgid = sg.get("GroupId")
            for ip_perm in sg.get("IpPermissions", []):
                from_port = ip_perm.get("FromPort")
                to_port = ip_perm.get("ToPort")
                ip_ranges = ip_perm.get("IpRanges", [])
                any_cidr = any(r.get("CidrIp") == "0.0.0.0/0" for r in ip_ranges)
                if any_cidr:
                    # High risk if all ports or sensitive ports
                    if from_port is None and to_port is None:
                        sev = "CRITICAL"
                        desc = "Security Group allows inbound from 0.0.0.0/0 on ALL ports."
                        rem = "Restrict ingress to known CIDRs or use Load Balancer + SG references; avoid 0.0.0.0/0."
                    else:
                        # range; flag if sensitive or very wide
                        port_range = f"{from_port}-{to_port}" if to_port and from_port != to_port else f"{from_port}"
                        if (from_port in SENSITIVE_PORTS) or (to_port in SENSITIVE_PORTS):
                            sev = "CRITICAL"
                            desc = f"Security Group {sgid} allows inbound 0.0.0.0/0 on sensitive port {port_range}."
                            rem = "Limit SSH/RDP to VPN/bastion or specific IPs; prefer SSM Session Manager."
                        else:
                            sev = "HIGH"
                            desc = f"Security Group {sgid} allows inbound 0.0.0.0/0 on port(s) {port_range}."
                            rem = "Tighten ingress to least-privileged CIDRs; consider ALB+WAF."
                    add_finding(findings, account_id, region, "EC2", "SG.Ingress.0.0.0.0",
                                sev, "FAIL", sgid, desc,
                                rem,
                                "AWS Well-Architected: Security Pillar; CIS 4.1; AWS FSBP-EC2.SG.OpenIngress")
    return findings

def check_sg_egress_wide(session, account_id, region):
    findings = []
    ec2 = session.client("ec2", region_name=region)
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page.get("SecurityGroups", []):
            sgid = sg.get("GroupId")
            for ip_perm in sg.get("IpPermissionsEgress", []):
                ip_ranges = ip_perm.get("IpRanges", [])
                any_cidr = any(r.get("CidrIp") == "0.0.0.0/0" for r in ip_ranges)
                all_ports = ip_perm.get("FromPort") is None and ip_perm.get("ToPort") is None
                if any_cidr and all_ports:
                    add_finding(
                        findings, account_id, region, "EC2", "SG.Egress.0.0.0.0",
                        "MEDIUM", "WARN", sgid,
                        "Security Group allows egress to 0.0.0.0/0 on all ports (data exfiltration risk).",
                        "Constrain egress to required CIDRs/ports; use VPC endpoints and egress controls.",
                        "AWS Well-Architected: Security Pillar; CIS 4.x; FSBP-EC2.SG.OpenEgress"
                    )
    return findings

def check_s3_public_and_encryption(session, account_id, region):
    findings = []
    s3 = session.client("s3", region_name=region)
    # Buckets are global; list once (region param ignored), but we still report with region for consistency.
    # We'll fetch per-bucket location and only include if matches 'region' (or all if unsure).
    all_buckets = s3.list_buckets().get("Buckets", [])
    for b in all_buckets:
        bucket = b["Name"]
        # Try to restrict by region
        try:
            loc = s3.get_bucket_location(Bucket=bucket).get("LocationConstraint")
            bucket_region = loc or "us-east-1"
            if bucket_region != region:
                continue
        except Exception:
            bucket_region = region  # if error, attribute to current region to avoid dropping
        # Public ACL?
        public_acl = False
        try:
            acl = s3.get_bucket_acl(Bucket=bucket)
            for grant in acl.get("Grants", []):
                gr = grant.get("Grantee", {})
                if gr.get("URI", "").endswith("AllUsers") or gr.get("URI", "").endswith("AuthenticatedUsers"):
                    public_acl = True
                    break
        except Exception:
            pass
        # Public policy?
        public_policy = False
        try:
            pol = s3.get_bucket_policy(Bucket=bucket)
            policy_doc = json.loads(pol["Policy"])
            for stmt in policy_doc.get("Statement", []):
                if stmt.get("Effect") == "Allow":
                    principal = stmt.get("Principal")
                    if principal == "*" or principal == {"AWS": "*"}:
                        public_policy = True
                        break
        except s3.exceptions.from_code("NoSuchBucketPolicy"):
            pass
        except Exception:
            pass

        if public_acl or public_policy:
            add_finding(
                findings, account_id, bucket_region, "S3", "S3.Public",
                "CRITICAL", "FAIL", bucket,
                "S3 bucket is publicly accessible via ACL and/or bucket policy.",
                "Block Public Access (account & bucket), remove public ACLs/policies, use presigned URLs/CloudFront with OAC.",
                "AWS FSBP-S3.1/2; CIS 2.1; WA Security Pillar"
            )

        # Default encryption
        try:
            enc = s3.get_bucket_encryption(Bucket=bucket)
            rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
            if not rules:
                raise Exception("No rules")
        except Exception:
            add_finding(
                findings, account_id, bucket_region, "S3", "S3.DefaultEncryption",
                "HIGH", "FAIL", bucket,
                "S3 bucket has no default encryption (SSE-S3 or SSE-KMS).",
                "Enable default encryption (SSE-KMS preferred) and enforce via bucket policy.",
                "AWS FSBP-S3.3; CIS 2.2"
            )
    return findings

def check_iam_users_mfa_and_keys(session, account_id, region, stale_days=DEFAULT_UNUSED_KEY_AGE_DAYS):
    findings = []
    iam = session.client("iam")
    # Root account summary
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled", 0) == 0:
            add_finding(
                findings, account_id, "global", "IAM", "Root.MFA",
                "CRITICAL", "FAIL", "root",
                "Root account MFA is NOT enabled.",
                "Enable hardware/virtual MFA on the root account and avoid using root for daily ops.",
                "CIS 1.1; AWS FSBP-IAM.RootMFA"
            )
        if summary.get("AccessKeysPresent", 0) > 0:
            add_finding(
                findings, account_id, "global", "IAM", "Root.AccessKeys",
                "CRITICAL", "FAIL", "root",
                "Root account has access keys present.",
                "Delete any root access keys. Use individual IAM users/roles.",
                "CIS 1.2; AWS FSBP-IAM.RootKeys"
            )
    except Exception:
        pass

    # Users without MFA, stale keys
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            uname = user["UserName"]
            # MFA
            mfa = iam.list_mfa_devices(UserName=uname).get("MFADevices", [])
            if not mfa:
                add_finding(
                    findings, account_id, "global", "IAM", "User.MFA",
                    "HIGH", "FAIL", uname,
                    f"IAM user '{uname}' does not have MFA enabled.",
                    "Assign a virtual/hardware MFA device and enforce MFA via IAM policies.",
                    "CIS 1.6; AWS FSBP-IAM.UserMFA"
                )
            # Access keys usage age
            keys = iam.list_access_keys(UserName=uname).get("AccessKeyMetadata", [])
            for k in keys:
                kid = k["AccessKeyId"]
                last_used = iam.get_access_key_last_used(AccessKeyId=kid).get("AccessKeyLastUsed", {})
                last_used_date = last_used.get("LastUsedDate")
                if last_used_date:
                    age_days = (datetime.now(timezone.utc) - last_used_date).days
                    if age_days > stale_days:
                        add_finding(
                            findings, account_id, "global", "IAM", "User.Key.Stale",
                            "MEDIUM", "WARN", f"{uname}:{kid}",
                            f"Access key unused for {age_days} days (> {stale_days}).",
                            "Rotate or deactivate stale access keys; prefer role-based access.",
                            "CIS 1.4/1.5"
                        )
                else:
                    # Never used; flag as warn
                    add_finding(
                        findings, account_id, "global", "IAM", "User.Key.NeverUsed",
                        "MEDIUM", "WARN", f"{uname}:{kid}",
                        "Access key has never been used.",
                        "Remove unused keys; adopt least privilege and role-based access.",
                        "CIS 1.4/1.5"
                    )

    # Account password policy
    try:
        pol = iam.get_account_password_policy()["PasswordPolicy"]
        # quick heuristic checks
        reqs = [
            ("RequireSymbols", True),
            ("RequireNumbers", True),
            ("RequireUppercaseCharacters", True),
            ("RequireLowercaseCharacters", True),
            ("MinimumPasswordLength", 14),
            ("PasswordReusePrevention", 24),
            ("MaxPasswordAge", 90),
        ]
        for field, expected in reqs:
            val = pol.get(field)
            bad = False
            if isinstance(expected, bool):
                bad = (val is not True)
            else:
                # numeric policy: require >= or <= depending on field
                if field in ("MinimumPasswordLength", "PasswordReusePrevention"):
                    bad = (val is None or val < expected)
                elif field == "MaxPasswordAge":
                    bad = (val is None or val > expected)
            if bad:
                add_finding(
                    findings, account_id, "global", "IAM", "Account.PasswordPolicy",
                    "MEDIUM", "WARN", "account_password_policy",
                    f"Password policy '{field}' not meeting recommended baseline (current: {val}, expected: {expected}).",
                    "Strengthen the account password policy (len ≥14, complexity on, reuse ≥24, max age ≤90 days).",
                    "CIS 1.9; AWS WA Security"
                )
    except iam.exceptions.NoSuchEntityException:
        add_finding(
            findings, account_id, "global", "IAM", "Account.PasswordPolicy",
            "HIGH", "FAIL", "account_password_policy",
            "No account password policy is configured.",
            "Define a strong password policy (length ≥14, complexity on, reuse prevention, rotation).",
            "CIS 1.8/1.9"
        )
    except Exception:
        pass

    return findings

def check_cloudtrail_enabled(session, account_id, region):
    findings = []
    ct = session.client("cloudtrail", region_name=region)
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        if not trails:
            add_finding(
                findings, account_id, region, "CloudTrail", "CloudTrail.Enabled",
                "HIGH", "FAIL", "cloudtrail",
                "No CloudTrail trail found (reduced forensic visibility).",
                "Create an org or multi-region CloudTrail, log to S3 + CloudWatch Logs with SSE-KMS.",
                "CIS 3.x; AWS FSBP-CT.Enabled"
            )
        else:
            # Optionally check multi-region & log file validation
            for t in trails:
                if not t.get("IsMultiRegionTrail", False):
                    add_finding(
                        findings, account_id, region, "CloudTrail", "CloudTrail.MultiRegion",
                        "MEDIUM", "WARN", t.get("Name", "trail"),
                        "CloudTrail trail is not multi-region.",
                        "Enable multi-region trail to capture all regions; store in central S3 with KMS.",
                        "CIS 3.1; WA Security"
                    )
    except Exception:
        pass
    return findings

def check_ebs_default_encryption(session, account_id, region):
    findings = []
    ec2 = session.client("ec2", region_name=region)
    try:
        resp = ec2.get_ebs_encryption_by_default()
        if not resp.get("EbsEncryptionByDefault", False):
            add_finding(
                findings, account_id, region, "EC2/EBS", "EBS.DefaultEncryption",
                "HIGH", "FAIL", "account-ebs-default",
                "EBS default encryption is disabled.",
                "Enable EBS default encryption (prefer CMK) at the account/region level.",
                "CIS 2.x; FSBP-EBS.DefaultEncryption"
            )
    except Exception:
        pass
    return findings

def check_ec2_imdsv2(session, account_id, region):
    findings = []
    ec2 = session.client("ec2", region_name=region)
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate():
        for r in page.get("Reservations", []):
            for inst in r.get("Instances", []):
                iid = inst["InstanceId"]
                imds = inst.get("MetadataOptions", {})
                http_tokens = imds.get("HttpTokens")
                if http_tokens != "required":
                    add_finding(
                        findings, account_id, region, "EC2", "EC2.IMDSv2",
                        "HIGH", "FAIL", iid,
                        "Instance does not enforce IMDSv2 (HttpTokens != 'required').",
                        "Modify instance metadata options to require IMDSv2.",
                        "AWS FSBP-EC2.IMDSv2"
                    )
    return findings

def check_rds_public(session, account_id, region):
    findings = []
    rds = session.client("rds", region_name=region)
    paginator = rds.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        for db in page.get("DBInstances", []):
            if db.get("PubliclyAccessible", False):
                add_finding(
                    findings, account_id, region, "RDS", "RDS.Public",
                    "CRITICAL", "FAIL", db.get("DBInstanceIdentifier"),
                    "RDS instance is publicly accessible.",
                    "Disable public access; place DB in private subnets with SG/VPC controls and use bastion/SSM.",
                    "CIS 4.x; FSBP-RDS.Public"
                )
    return findings

def check_ecr_scan_on_push(session, account_id, region):
    findings = []
    ecr = session.client("ecr", region_name=region)
    paginator = ecr.get_paginator("describe_repositories")
    for page in paginator.paginate():
        for repo in page.get("repositories", []):
            rid = repo["repositoryName"]
            # registry scanning is another feature; here we check per-repo setting
            try:
                pol = ecr.get_repository_policy(repositoryName=rid)
                # policy existence ≠ scanning
            except ecr.exceptions.RepositoryPolicyNotFoundException:
                pass
            # Describe image scanning config (for newer accounts)
            resp = ecr.describe_image_scanning_configuration(repositoryName=rid)
            cfg = resp.get("imageScanningConfiguration", {})
            if cfg.get("scanOnPush") is not True:
                add_finding(
                    findings, account_id, region, "ECR", "ECR.ScanOnPush",
                    "MEDIUM", "WARN", rid,
                    "ECR repository does not have scan-on-push enabled.",
                    "Enable scan-on-push for ECR repositories and consider registry-wide enhanced scanning.",
                    "FSBP-ECR.ScanOnPush"
                )
    return findings

def check_guardduty_enabled(session, account_id, region):
    findings = []
    gd = session.client("guardduty", region_name=region)
    try:
        detectors = gd.list_detectors().get("DetectorIds", [])
        if not detectors:
            add_finding(
                findings, account_id, region, "GuardDuty", "GuardDuty.Enabled",
                "HIGH", "FAIL", "guardduty",
                "GuardDuty is not enabled in this region.",
                "Enable GuardDuty (ideally organization-wide) with S3/Malware Protection.",
                "FSBP-GD.Enabled"
            )
    except Exception:
        pass
    return findings

def check_kms_rotation(session, account_id, region):
    findings = []
    kms = session.client("kms", region_name=region)
    paginator = kms.get_paginator("list_keys")
    for page in paginator.paginate():
        for key in page.get("Keys", []):
            kid = key["KeyId"]
            try:
                meta = kms.describe_key(KeyId=kid)["KeyMetadata"]
                # Skip AWS managed keys
                if meta.get("KeyManager") == "CUSTOMER":
                    rot = kms.get_key_rotation_status(KeyId=kid).get("KeyRotationEnabled", False)
                    if not rot:
                        add_finding(
                            findings, account_id, region, "KMS", "KMS.Rotation",
                            "MEDIUM", "WARN", meta.get("Arn"),
                            "Customer-managed KMS key rotation is disabled.",
                            "Enable annual rotation for CMKs used broadly for data-at-rest.",
                            "FSBP-KMS.Rotation"
                        )
            except Exception:
                pass
    return findings

# ---------- main orchestration ----------

CHECKS = [
    ("EC2 SG: open ingress", check_sg_ingress_open),
    ("EC2 SG: wide egress", check_sg_egress_wide),
    ("S3: public & encryption", check_s3_public_and_encryption),
    ("IAM: MFA & keys & policy", check_iam_users_mfa_and_keys),
    ("CloudTrail: enabled", check_cloudtrail_enabled),
    ("EBS: default encryption", check_ebs_default_encryption),
    ("EC2: IMDSv2 enforced", check_ec2_imdsv2),
    ("RDS: public", check_rds_public),
    ("ECR: scan on push", check_ecr_scan_on_push),
    ("GuardDuty: enabled", check_guardduty_enabled),
    ("KMS: key rotation", check_kms_rotation),
]

def parse_args():
    ap = argparse.ArgumentParser(description="AWS High-Risk Auditor (boto3)")
    ap.add_argument("--profile", help="AWS profile name to use")
    ap.add_argument("--regions", nargs="+", help="Space-separated list of regions to scan (default: all available)")
    ap.add_argument("--stale-key-days", type=int, default=DEFAULT_UNUSED_KEY_AGE_DAYS,
                    help=f"Age threshold for stale IAM access keys (default {DEFAULT_UNUSED_KEY_AGE_DAYS})")
    ap.add_argument("--json-out", default="aws_audit_report.json")
    ap.add_argument("--csv-out", default="aws_audit_report.csv")
    return ap.parse_args()

def main():
    args = parse_args()
    session_kwargs = {}
    if args.profile:
        session_kwargs["profile_name"] = args.profile
    session = boto3.Session(**session_kwargs)

    account_id = get_account_id(session)

    if args.regions:
        regions = args.regions
    else:
        regions = get_all_regions(session)

    print(f"[+] Auditing account {account_id} in {len(regions)} region(s)...")

    findings = []

    # Global-only checks can be called once (but we keep region reporting consistent)
    for region in regions:
        print(f"  -> Region: {region}")

        for label, fn in CHECKS:
            try:
                if fn == check_iam_users_mfa_and_keys:
                    part = fn(session, account_id, region, stale_days=args.stale_key_days)
                else:
                    part = fn(session, account_id, region)
                findings.extend(part)
                print(f"     - {label}: +{len(part)} finding(s)")
            except KeyboardInterrupt:
                print("\nAborted.")
                sys.exit(1)
            except Exception as e:
                # Non-fatal: record info for visibility
                add_finding(
                    findings, account_id, region, "SYSTEM", "Check.Error",
                    "INFO", "INFO", label,
                    f"Check '{label}' failed with error: {e}",
                    "Ensure permissions and service availability; re-run.",
                    "N/A"
                )

    # Quick summary
    total = len(findings)
    fails = sum(1 for f in findings if f["status"] == "FAIL")
    warns = sum(1 for f in findings if f["status"] == "WARN")
    passes = sum(1 for f in findings if f["status"] == "PASS")

    print(f"\n[=] Findings: total={total}, FAIL={fails}, WARN={warns}, PASS={passes}")
    write_reports(findings, out_json=args.json_out, out_csv=args.csv_out)
    print(f"[✓] Wrote {args.json_out} and {args.csv_out}")

if __name__ == "__main__":
    main()
