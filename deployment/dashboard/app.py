import json
import time
import os
from flask import Flask, Response, render_template

app = Flask(__name__)
FEED_FILE = "/tmp/sensor_feed.jsonl"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/stream")
def stream():
    def generate():
        # Clear old data on connect so chart starts fresh
        open(FEED_FILE, "w").close()
        yield "data: {\"status\": \"waiting\"}\n\n"

        while True:
            if not os.path.exists(FEED_FILE):
                time.sleep(0.5)
                continue
            with open(FEED_FILE, "r") as f:
                lines = f.readlines()
            if lines:
                # Send all buffered lines then clear
                for line in lines:
                    line = line.strip()
                    if line:
                        yield f"data: {line}\n\n"
                open(FEED_FILE, "w").close()
            time.sleep(1)

    return Response(generate(), mimetype="text/event-stream")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
