import subprocess
import json
import os

# List of Volatility plugins used by the dashboard
plugins = [
    "windows.info.Info",
    "windows.pslist.PsList",
    "windows.pstree.PsTree",
    "windows.cmdline.CmdLine",
    "windows.dlllist.DllList",
    "windows.malfind.Malfind",
    "windows.vadinfo.VadInfo",
    "windows.netscan.NetScan"
]

# Export the plugin list so it can be used elsewhere in the app
PLUGINS = plugins

# Base project path and Volatility launcher path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VOL_PATH = os.path.join(BASE_DIR, "volatility3", "vol.py")


def normalize_output(parsed):
    """
    Convert Volatility output into a consistent structure
    with 'columns' and 'rows' for the frontend.
    """

    # If the output is already in the expected format, return it as-is
    if isinstance(parsed, dict) and "rows" in parsed:
        return parsed

    # If the output is a list of dictionaries, convert it into columns/rows
    if isinstance(parsed, list):

        if len(parsed) == 0:
            return {"columns": [], "rows": []}

        columns = list(parsed[0].keys())
        rows = []

        for item in parsed:
            rows.append(list(item.values()))

        return {
            "columns": columns,
            "rows": rows
        }

    # Fallback if the returned format is not recognised
    return {
        "columns": ["error"],
        "rows": [["Unknown output format"]]
    }


def run_plugin(dumpfile, plugin):
    """
    Run a single Volatility plugin against the selected memory dump
    and return its output in a structured format.
    """

    command = [
        "python",
        VOL_PATH,
        "-f",
        dumpfile,
        "-r",
        "json",
        plugin
    ]

    try:
        # Run Volatility as a subprocess so the dashboard can capture its output
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            cwd=BASE_DIR
        )

        # Return a clear error if the plugin failed or is unsupported
        if result.returncode != 0 or "Unable to validate" in result.stderr:
            return {
                "columns": ["error"],
                "rows": [[f"{plugin} failed or not supported on this memory dump"]]
            }

        output = result.stdout.strip()

        # Return an error if Volatility produced no usable output
        if not output:
            return {
                "columns": ["error"],
                "rows": [["Volatility returned no output"]]
            }

        # Try to parse the JSON returned by Volatility
        try:
            parsed = json.loads(output)
        except:
            return {
                "columns": ["error"],
                "rows": [["Failed to parse Volatility output"]]
            }

        # Normalize the parsed data into the format expected by the UI
        return normalize_output(parsed)

    except Exception as e:
        # Catch unexpected errors so the app does not crash
        return {
            "columns": ["error"],
            "rows": [[str(e)]]
        }