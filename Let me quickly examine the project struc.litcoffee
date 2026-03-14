Let me quickly examine the project structure and dependencies to give you accurate setup commands.

Viewed pyproject.toml:1-33
Searched for files: requirements*
Listed directory leak-check
Viewed requirements.txt:1-9
Viewed .env.example

Let me also check how the web frontend is started:

Searched for "app.run"
Searched for "def main"
Viewed app.py:1-483
Viewed cli.py:1-323

Here are all the commands needed to set up and run the LeakCheck project on a different device, in sequential order:

```
# 1. Make sure you have Python 3.10+ installed
python --version

# 2. Navigate to the project folder (after copying/cloning it)
cd leak-check

# 3. Create a virtual environment
py -m venv .venv

# 4. Activate the virtual environment
# On Windows (PowerShell):
.venv\Scripts\Activate.ps1
# On Windows (CMD):
.venv\Scripts\activate.bat
# On macOS/Linux:
source .venv/bin/activate

# 5. Upgrade pip
python -m pip install --upgrade pip

# 6. Install the project in editable mode (installs all dependencies from pyproject.toml)
pip install -e .

# 7. Install dev dependencies (pytest)
pip install -e ".[dev]"

# 8. Verify the installation worked
leakcheck --help

# 9. (Optional) Test LLM connectivity — requires a local LLM server running on port 1234
leakcheck ping --endpoint http://127.0.0.1:1234/v1/chat/completions

# 10. Start the web dashboard (frontend)
leakcheck serve --host 0.0.0.0 --port 5000

# The dashboard will be available at http://localhost:5000
```

**Notes:**
- The project requires **Python 3.10 or higher**.
- The dependencies installed by `pip install -e .` are: `pydantic`, `pyyaml`, `rich`, `requests`, `python-dotenv`, `numpy`, `sentence-transformers`, `pyarrow`, and `flask`.
- For the LLM features (chat, campaigns) to work, you need a local LLM server running an OpenAI-compatible API at `http://127.0.0.1:1234/v1/chat/completions` (e.g. **LM Studio** with a model like `llama-3.2-3b-instruct` loaded). You can override this with the `LLM_ENDPOINT` and `LLM_MODEL` environment variables.
- The `sentence-transformers` package will auto-download the `all-MiniLM-L6-v2` model (~80MB) on first use.