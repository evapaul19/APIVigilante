import os
root = r'C:\api-security-system\targets'
for dirpath, dirnames, filenames in os.walk(root):
    rel = os.path.relpath(dirpath, root)
    depth = rel.count(os.sep)
    prefix = "  " * depth
    if depth == 0:
        print(f"{os.path.basename(dirpath)}/")
    else:
        print(f"{prefix}{os.path.basename(dirpath)}/")
    for f in filenames[:3]:
        print(f"  {prefix}  {f}")