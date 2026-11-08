#!/usr/bin/env python3
"""r2_upload.py -- minimal, R2-safe S3 primitives for the image publisher.

Isolated from publish-to-r2.sh so the one Cloudflare-R2 quirk lives in exactly
one place: R2 rejects the data-integrity *checksum trailers* that recent
botocore (>= 1.36, "when_supported" default) attaches to streaming uploads
(x-amz-checksum-* / STREAMING-UNSIGNED-PAYLOAD-TRAILER). We defuse it three ways,
belt-and-suspenders:

  1. botocore Config(request_checksum_calculation="when_required",
     response_checksum_validation="when_required")   -- the documented knob.
  2. AWS_REQUEST_CHECKSUM_CALCULATION / AWS_RESPONSE_CHECKSUM_VALIDATION env
     backstop (older/newer botocore read one or the other).
  3. Every part/object Body is passed as an in-memory `bytes` object, never a
     file handle, so botocore computes a flat header checksum (accepted) instead
     of a streaming trailer (rejected).

Multipart is done by hand in fixed 100 MiB chunks (R2 requires every part except
the last to be the same size, and >= 5 MiB) with explicit abort-on-failure so a
crashed publish never leaves a dangling multipart upload accruing storage.

Credentials come from the environment only (AWS_ACCESS_KEY_ID /
AWS_SECRET_ACCESS_KEY), read by boto3 itself -- nothing is hardcoded here.

Subcommands (primitives; publish-to-r2.sh orchestrates ordering + signing):
  put   --key K --file F [--content-type CT] [--cache-control CC]
  get   --key K --file F           # exit 3 if the key does not exist
  head  --key K                    # prints ContentLength, or "MISSING"

Endpoint/bucket resolution (flags override env):
  --endpoint / R2_ENDPOINT_URL, or derived https://$R2_ACCOUNT_ID.r2.cloudflarestorage.com
  --bucket   / R2_BUCKET
"""
import argparse
import os
import sys

CHUNK = 100 * 1024 * 1024  # 100 MiB parts (R2: uniform, >= 5 MiB except last)


def _eprint(*a):
    print(*a, file=sys.stderr)


def _client(endpoint):
    try:
        import boto3
        from botocore.config import Config
    except ImportError as e:  # pragma: no cover - environment problem
        _eprint("r2_upload: boto3 is required (pip install boto3):", e)
        sys.exit(2)

    # Backstop env for botocore versions that read env but not the Config kwargs.
    os.environ.setdefault("AWS_REQUEST_CHECKSUM_CALCULATION", "when_required")
    os.environ.setdefault("AWS_RESPONSE_CHECKSUM_VALIDATION", "when_required")

    cfg_kwargs = {"region_name": "auto"}
    try:
        cfg = Config(
            region_name="auto",
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
        )
    except TypeError:
        # Older botocore without the checksum kwargs: env backstop still applies.
        cfg = Config(**cfg_kwargs)

    return boto3.client("s3", endpoint_url=endpoint, config=cfg)


def _resolve(args):
    endpoint = args.endpoint or os.environ.get("R2_ENDPOINT_URL")
    if not endpoint:
        acct = os.environ.get("R2_ACCOUNT_ID")
        if acct:
            endpoint = f"https://{acct}.r2.cloudflarestorage.com"
    if not endpoint:
        _eprint("r2_upload: set --endpoint, R2_ENDPOINT_URL, or R2_ACCOUNT_ID")
        sys.exit(2)
    bucket = args.bucket or os.environ.get("R2_BUCKET")
    if not bucket:
        _eprint("r2_upload: set --bucket or R2_BUCKET")
        sys.exit(2)
    return endpoint, bucket


def _extra(content_type, cache_control):
    extra = {}
    if content_type:
        extra["ContentType"] = content_type
    if cache_control:
        extra["CacheControl"] = cache_control
    return extra


def cmd_put(args):
    endpoint, bucket = _resolve(args)
    client = _client(endpoint)
    extra = _extra(args.content_type, args.cache_control)
    size = os.path.getsize(args.file)

    if size <= CHUNK:
        with open(args.file, "rb") as f:
            body = f.read()
        client.put_object(Bucket=bucket, Key=args.key, Body=body, **extra)
        _eprint(f"r2_upload: put {args.key} ({size} bytes, single)")
        return 0

    mpu = client.create_multipart_upload(Bucket=bucket, Key=args.key, **extra)
    upload_id = mpu["UploadId"]
    parts = []
    try:
        n = 1
        with open(args.file, "rb") as f:
            while True:
                chunk = f.read(CHUNK)  # bytes, not a stream -> flat checksum
                if not chunk:
                    break
                r = client.upload_part(
                    Bucket=bucket, Key=args.key, PartNumber=n,
                    UploadId=upload_id, Body=chunk,
                )
                parts.append({"ETag": r["ETag"], "PartNumber": n})
                _eprint(f"r2_upload: part {n} ({len(chunk)} bytes)")
                n += 1
        client.complete_multipart_upload(
            Bucket=bucket, Key=args.key, UploadId=upload_id,
            MultipartUpload={"Parts": parts},
        )
        _eprint(f"r2_upload: put {args.key} ({size} bytes, {len(parts)} parts)")
        return 0
    except BaseException as e:  # abort so we never leak a dangling MPU
        try:
            client.abort_multipart_upload(
                Bucket=bucket, Key=args.key, UploadId=upload_id)
            _eprint(f"r2_upload: aborted multipart upload for {args.key}")
        except Exception as ae:  # pragma: no cover
            _eprint(f"r2_upload: WARNING could not abort MPU {upload_id}: {ae}")
        _eprint(f"r2_upload: FAILED put {args.key}: {e}")
        return 1


def cmd_get(args):
    endpoint, bucket = _resolve(args)
    client = _client(endpoint)
    try:
        from botocore.exceptions import ClientError
    except ImportError:  # pragma: no cover
        ClientError = Exception
    try:
        client.download_file(bucket, args.key, args.file)
        _eprint(f"r2_upload: got {args.key} -> {args.file}")
        return 0
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("404", "NoSuchKey", "NotFound"):
            _eprint(f"r2_upload: {args.key} MISSING")
            return 3
        _eprint(f"r2_upload: get {args.key} failed: {e}")
        return 1


def cmd_head(args):
    endpoint, bucket = _resolve(args)
    client = _client(endpoint)
    try:
        from botocore.exceptions import ClientError
    except ImportError:  # pragma: no cover
        ClientError = Exception
    try:
        r = client.head_object(Bucket=bucket, Key=args.key)
        print(r["ContentLength"])
        return 0
    except ClientError:
        print("MISSING")
        return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="R2-safe S3 primitives")
    p.add_argument("--endpoint")
    p.add_argument("--bucket")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("put")
    sp.add_argument("--key", required=True)
    sp.add_argument("--file", required=True)
    sp.add_argument("--content-type", default="")
    sp.add_argument("--cache-control", default="")
    sp.set_defaults(func=cmd_put)

    sg = sub.add_parser("get")
    sg.add_argument("--key", required=True)
    sg.add_argument("--file", required=True)
    sg.set_defaults(func=cmd_get)

    sh = sub.add_parser("head")
    sh.add_argument("--key", required=True)
    sh.set_defaults(func=cmd_head)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
