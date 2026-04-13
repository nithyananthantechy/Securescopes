import os, json, datetime, urllib.parse

HISTORY_DIR = r"C:\Users\Nithyananthan\AppData\Roaming\Code\User\History"
for folder in os.listdir(HISTORY_DIR):
    folder_path = os.path.join(HISTORY_DIR, folder)
    entries_file = os.path.join(folder_path, "entries.json")
    if not os.path.isfile(entries_file): continue
    with open(entries_file, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
            resource = data.get("resource", "")
            if "index.html" in resource or "app.py" in resource:
                for entry in data.get("entries", []):
                    ts = entry.get("timestamp")
                    file_id = entry.get("id")
                    if ts > 1750000000000: # recent
                        dt = datetime.datetime.fromtimestamp(ts/1000).strftime('%Y-%m-%d %H:%M:%S')
                        print(f"Resource: {resource} -> {dt} -> {os.path.join(folder_path, file_id)}")
        except Exception:
            pass
