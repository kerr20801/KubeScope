"""
KubeScope - Codebase Integrity & Anti-Tamper Verification Tool
Zero-dependency: uses Python 3 standard library (hashlib, os, sys)
Verifies that all files in KubeScope match their cryptographic SHA-256 hashes.
Protects against software supply chain poisoning, MitM tampering, or unauthorized code changes.
"""
import os
import sys
import hashlib

# Ensure Windows terminal handles UTF-8 correctly
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CHECKSUM_FILE = os.path.join(BASE_DIR, "SHA256SUMS.txt")

def calculate_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def generate_checksums():
    """Generates SHA256SUMS.txt for all tracked project files."""
    exclude_dirs = {".git", "__pycache__", ".vscode", ".idea"}
    exclude_files = {"SHA256SUMS.txt"}
    
    entries = []
    for root, dirs, files in os.walk(BASE_DIR):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for f in sorted(files):
            if f in exclude_files or f.endswith(".pyc"):
                continue
            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, BASE_DIR).replace("\\", "/")
            file_hash = calculate_sha256(full_path)
            entries.append(f"{file_hash}  {rel_path}")

    with open(CHECKSUM_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(entries) + "\n")
    print(f"[*] 已生成代碼防偽指紋清單：{CHECKSUM_FILE} (共 {len(entries)} 個檔案)")

def verify_checksums() -> bool:
    """Verifies all files against SHA256SUMS.txt."""
    if not os.path.exists(CHECKSUM_FILE):
        print("[!] 找不到 SHA256SUMS.txt，請先執行 `python verify_integrity.py --generate` 生成校驗檔！")
        return False

    print("=======================================================")
    print("  🛡️  KubeScope 代碼防偽與供應鏈完整性校驗儀")
    print("=======================================================")

    with open(CHECKSUM_FILE, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    total = 0
    passed = 0
    failed = []
    missing = []

    for line in lines:
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("#"):
            continue
        parts = line_clean.split(None, 1)
        if len(parts) != 2:
            continue
        expected_hash, rel_path = parts[0], parts[1].strip()
        full_path = os.path.join(BASE_DIR, rel_path.replace("/", os.sep))
        total += 1

        if not os.path.exists(full_path):
            missing.append(rel_path)
            print(f"  [MISSING] 遺失檔案: {rel_path}")
            continue

        actual_hash = calculate_sha256(full_path)
        if actual_hash == expected_hash:
            passed += 1
            print(f"  [OK]  {rel_path}")
        else:
            failed.append(rel_path)
            print(f"  [TAMPERED / 警告] 檔案遭篡改: {rel_path}")

    print("-------------------------------------------------------")
    print(f"  檢驗結果：總數 {total} | 通過 {passed} | 篡改 {len(failed)} | 遺失 {len(missing)}")

    if len(failed) == 0 and len(missing) == 0:
        print("  🟢 驗證通過！所有原始碼與靜態資源均符合官方 SHA-256 簽名，未受任何竄改！")
        print("=======================================================")
        return True
    else:
        print("  🔴 警告！檢測到部分檔案與官方校驗指紋不符，可能遭遇供應鏈攻擊或非預期修改！")
        print("=======================================================")
        return False

if __name__ == "__main__":
    if "--generate" in sys.argv:
        generate_checksums()
    else:
        success = verify_checksums()
        sys.exit(0 if success else 1)
