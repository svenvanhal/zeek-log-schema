# Zeek Log Schema

Static ZeekScript source code analyzer that generates schemas for log streams. Streamlit app included to compare Zeek versions and highlight the differences.

## Usage - Streamlit
Clone this repository and run the Streamlit app – from the repository root – using either Docker or `uv`.

#### Docker
```shell
docker compose up -d
```

The app is now available at http://localhost:8080/.

#### uv
```shell
uv run -- streamlit run app/app.py
```
The app should open automatically. If not, try http://localhost:8501/ or follow the instructions in the `streamlit` command output.

---

Select two Zeek versions to compare and optionally select some [Zeek packages](https://packages.zeek.org/) or provide your own custom script files to analyze. Hit `Compare >` and wait for the analyzer to finish, which may take around 20 seconds.

![Zeek Schema Comparison](./readme_files/streamlit_input_form.png)

The app will now display the schema for each log stream, including changes between the selected versions. 

<table><tr>
    <td width="33.33%">
        <img width="100%" alt="Image showing output stream updates" src="./readme_files/streamlit_example_output_streams_added.png"><br>
        <b>New output streams (log files)</b>
    </td>
    <td width="33.33%">
        <img width="100%" alt="Image showing schema inspection and changes" src="./readme_files/streamlit_example_schemas_changed.png"><br>
        <b>Schema per output stream</b>
    </td>
    <td width="33.33%">
        <img width="100%" alt="Image showing field name, type and location diff" src="./readme_files/streamlit_example_added_fields.png"><br>
        <b>Changes highlighted</b>
    </td>
</tr></table>

## Usage - Library

Minimal example:

```python
from pathlib import Path

from zeek_log_schema import process_zeek_source

# Path to Zeek source code to analyze, for example:
# $ git clone https://github.com/zeek/zeek.git /tmp/zeek
base_path = Path('/tmp/zeek/')

# Analyze ZeekScript files
result = process_zeek_source(base_path.glob('**/*.zeek'))

# Alternatively, look for both .bro and .zeek files:
# from itertools import chain
# result = process_zeek_source(
#     chain(base_path.glob('**/*.bro'), base_path.glob('**/*.zeek'))
# )

print(result)
```

## Development

First time setup:

```shell
uv venv
```

To hot reload Python module code from `zeek_log_schema` in Streamlit, start the app with `PYTHONPATH=.` from the repository root.

```shell
PYTHONPATH=. uv run -- streamlit run app/app.py
```
