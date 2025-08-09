import sys

# Add parent directory to path so Streamlit can find our module
# N.B. This line must appear before any imports from zeek_log_schema
sys.path.extend('../')

import tempfile
from io import BytesIO
from zipfile import ZipFile
from itertools import chain

from streamlit.runtime.uploaded_file_manager import UploadedFile
from pathlib import Path
from typing import Any

import streamlit as st
from git import Repo
from packaging import version

from zeek_log_schema import MemoryFile, ParseError, RecordDeclaration, process_zeek_source

ZEEK_REPO_URL = r"https://github.com/zeek/zeek.git"
TMP_WORKING_DIR = Path(tempfile.gettempdir()) / 'zeek-schema-comparison-tool-streamlit'

st.set_page_config(layout="wide")


def field_comparison_subset(f, compare_fields=None):
    subset = [f.name, f.type.name if isinstance(f.type, RecordDeclaration) else f.type]

    if compare_fields and compare_fields.get('meta.filename', False):
        subset.append(f.meta['filename'])

    return tuple(subset)


@st.cache_data(show_spinner=False, )
def analyze_source(_repo: Repo, input_data: dict) -> Any:
    # Checkout repository at tag
    _repo.git.checkout(input_data['tag'], force=True)

    # Determine script extension based on version
    ext = get_name_for_version(input_data['tag']).lower()

    # Unzip custom scripts
    custom_scripts = [_extract_uploaded_file(uf) for uf in input_data.get('custom_scripts', None)]

    # Run analysis
    zeek_script_files = list((TMP_WORKING_DIR / 'scripts/').glob(f"**/*.{ext}"))
    result = process_zeek_source(chain(zeek_script_files, *custom_scripts))

    # Gather and return results
    return result


def get_name_for_version(v: str) -> str:
    return 'Bro' if version.parse(v) < version.parse('v3.0.0') else 'Zeek'


def _generate_report__overview(old, new, changes) -> None:
    meta_old, old = old
    meta_new, new = new

    st.markdown("<br>", unsafe_allow_html=True)

    # st.subheader("Overview")

    def _make_column(meta, data, diff_with_prev=False):
        release_date = f"{meta['tag'].commit.committed_datetime:%Y-%m-%d}"

        streams, records = data

        output = f"""
        **{get_name_for_version(meta['version'])} version {meta['version']}**<br>
        Release date: {release_date}
        <br><br>
        {len(streams)} log streams
        """

        if diff_with_prev:
            _added, _removed = len(changes['streams']['added']), len(changes['streams']['removed'])
            if _added or _removed:
                _c = []
                if _added:   _c.append(f'+{_added}')
                if _removed: _c.append(f'-{_removed}')
                output += f' ({", ".join(_c)})'

        st.markdown(output, unsafe_allow_html=True)

    col1, col2 = st.columns([1, 1])
    with col1:
        _make_column(meta_old, old, diff_with_prev=False)
    with col2:
        _make_column(meta_new, new, diff_with_prev=True)


def _generate_report__log_streams(old, new, stream_changes) -> None:
    meta_old, old = old
    meta_new, new = new

    added = stream_changes.get('added', set())
    removed = stream_changes.get('removed', set())

    st.subheader("Output Streams", help="Output streams are ultimately consumed somewhere, in practice often written to disk (for example \"conn.log\").")

    if not added and not removed:
        st.text("No output streams were added or removed between these versions.")

    else:
        col1, col2 = st.columns([1, 1])

        with col1:
            if removed:
                st.write(f"{len(removed)} output streams removed since {meta_old['version']}")
                st.code('\n'.join(map(lambda r: f'[-] {r}.log', sorted(removed))))
            else:
                st.write('No removals.')

        with col2:
            if added:
                st.write(f"{len(added)} output streams added in {meta_new['version']}")
                st.code('\n'.join(map(lambda r: f'[+] {r}.log', sorted(added))))
            else:
                st.write('No additions.')


def _print_zeek_log_diff(old, new, name, change_report, only_changes=False, collapse=True, compare_fields: dict = None):
    _log_has_changed = change_report['status'] != 'unchanged'
    _old = change_report['objects']['old']
    _new = change_report['objects']['new']
    _old_record = getattr(_old, 'record', None)
    _new_record = getattr(_new, 'record', None)

    old_meta, _ = old
    new_meta, _ = new

    if only_changes and not _log_has_changed:
        return False

    expander_title = f"{name}.log"
    if _log_has_changed:
        expander_title += f" `{change_report['status']}`"

    def print_field(f, status=None):

        output = ""

        name_fill_len = 43
        match status:
            case "added":
                output += "[+] "
            case "removed":
                output += "[-] "
            case "changed":
                output += "[/] "
            case _:
                name_fill_len += 4

        _type = f.type
        if f.nested_type:
            _type += f"[{f.nested_type}]"

        output += f"{f.name:<{name_fill_len}}{_type:<20}# {f.meta['filename']}"

        return output

    with st.expander(expander_title, expanded=not collapse):

        col1, col2 = st.columns([1, 1])

        if change_report['status'] == 'added':

            with col2:
                st.code('\n'.join(print_field(f, "added") for f in _new_record.fields))

            st.caption(f"This record is used in output stream `{name}.log`, created in `{_new.meta['filename']}`.")

        elif change_report['status'] == 'removed':

            with col1:
                st.code('\n'.join(print_field(f, "removed") for f in _old_record.fields))

            st.caption(f"This record was used in output stream `{name}.log`, created in `{_old.meta['filename']}`.")

        elif change_report['status'] == 'changed':

            # Check if log stream has changed
            # Was defined in ... now defined in ...
            if _old.path != _new.path:
                st.write(f"The output stream for this record has changed from `{_old.path}.log` to `{_new.path}.log`.")

            old_fields = {f.name: f for f in _old_record.fields}
            new_fields = {f.name: f for f in _new_record.fields}

            all_field_names = {k: None for k in chain(new_fields.keys(), old_fields.keys())}

            lines_left = []
            lines_right = []

            for field_name in all_field_names:

                line_left = ""
                line_right = ""

                _o_field = old_fields.get(field_name, None)
                _n_field = new_fields.get(field_name, None)

                _old_field_subset = field_comparison_subset(_o_field, compare_fields) if _o_field else None
                _new_field_subset = field_comparison_subset(_n_field, compare_fields) if _n_field else None

                if _old_field_subset == _new_field_subset:
                    line_left += print_field(_o_field)
                    line_right += print_field(_o_field)
                else:
                    if _old_field_subset and _new_field_subset:
                        line_left += print_field(_o_field, None)
                        line_right += print_field(_n_field, 'changed')
                    else:

                        if not _old_field_subset:
                            line_left += f'-->'
                        else:
                            line_left += print_field(_o_field, 'removed')

                        if not _new_field_subset:
                            line_right += f'<--'
                        else:
                            line_right += print_field(_n_field, 'added')

                lines_left.append(line_left)
                lines_right.append(line_right)

            with col1:
                st.code('\n'.join(lines_left))
            with col2:
                st.code('\n'.join(lines_right))

            if _old.meta['filename'] == _new.meta['filename']:
                st.caption(f"This record is used in output stream `{name}.log`, created in `{_new.meta['filename']}`.")
            else:
                st.caption(
                    f"This record is used in output stream `{name}.log`.<br>:warning: The file in which this stream is created has changed from `{_old.meta['filename']}` to `{_new.meta['filename']}`.",
                    unsafe_allow_html=True)

        elif change_report['status'] == 'unchanged':
            st.code('\n'.join(print_field(f) for f in _new_record.fields))

            st.caption(f"This record is used in output stream `{name}.log`, created in `{_new.meta['filename']}`.")

    return True


def _generate_report__schemas(old, new, log_changes, compare_fields) -> None:
    st.subheader("Schemas")

    col1, col2 = st.columns([1, 1])
    with col1: only_changes = st.checkbox("Only show changes", value=True)
    with col2: collapsed = st.checkbox("Collapse", value=True)

    num_output_sections = sum(
        _print_zeek_log_diff(old, new, name, change_report, only_changes=only_changes, collapse=collapsed, compare_fields=compare_fields) for name, change_report in log_changes.items())

    if not num_output_sections:
        st.write("No changes.")


def diff(old, new, compare_fields: dict = None):
    meta_old, (old_streams, old_records) = old
    meta_new, (new_streams, new_records) = new

    # Changes in log streams
    streams_old = set(old_streams.keys())
    streams_new = set(new_streams.keys())
    diff_streams = {
        'added': streams_new - streams_old,
        'removed': streams_old - streams_new,
        'unchanged': streams_old.intersection(streams_new)
    }

    # Changes in schemas
    schema_changes = {}
    for name in sorted(streams_old.union(streams_new)):

        _old = old_streams.get(name, None)
        _new = new_streams.get(name, None)
        _old_record = getattr(_old, 'record', None)
        _new_record = getattr(_new, 'record', None)

        schema_changes[name] = {
            'objects': {
                'old': _old,
                'new': _new,
            }
        }

        in_old, in_new = name in old_streams, name in new_streams

        if not in_old and in_new:
            status = 'added'
        elif in_old and not in_new:
            status = 'removed'
        else:
            if _old_record == _new_record:
                status = 'unchanged'
            else:
                status = 'unchanged'

                _fields_old = set(field_comparison_subset(f, compare_fields) for f in _old_record.fields)
                _fields_new = set(field_comparison_subset(f, compare_fields) for f in _new_record.fields)

                if len(_fields_old.symmetric_difference(_fields_new)) > 0:
                    status = 'changed'

                schema_changes[name]['objects']['field_changes'] = {'old': _fields_old, 'new': _fields_new}

        # Add status
        schema_changes[name]['status'] = status

    return {
        'streams': diff_streams,
        'logs': schema_changes
    }


def _extract_uploaded_file(uploaded_file: UploadedFile) -> list[MemoryFile]:
    if uploaded_file is None:
        return []

    zip_name = str(Path(uploaded_file.name).with_suffix(''))
    file_bytes = BytesIO(uploaded_file.getvalue())

    with ZipFile(file_bytes) as zip_file:
        return [MemoryFile(Path(f"scripts/_custom/{name.removeprefix(zip_name + '/')}"), BytesIO(zip_file.read(name))) for name in zip_file.namelist()]


def generate_report(repo: Repo, old: dict, new: dict, compare_fields: dict = None) -> None:
    # Analyze source files
    analysis = []
    for data in (old, new):
        with st.spinner(f"Analyzing {data['tag']}"):
            meta = {
                'version': data['tag'],
                'tag': repo.tags[data['tag']]
            }

            try:
                analysis.append((meta, analyze_source(repo, data)))
            except ParseError as e:
                st.error(
                    f'**Error:** could not parse source files for {get_name_for_version(meta["version"])} {meta["version"]}. This usually happens for older source files, which use a now no longer supported ZeekScript syntax.')
                with st.expander("Strack trace:"):
                    st.exception(e)
                return

    result_old, result_new = analysis

    # Determine changes
    changes = diff(result_old, result_new, compare_fields)

    st.divider()

    # Generate and display report
    _generate_report__overview(result_old, result_new, changes)

    st.divider()

    _generate_report__log_streams(result_old, result_new, changes.get('streams', {}))

    st.divider()

    _generate_report__schemas(result_old, result_new, changes.get('logs', {}), compare_fields=compare_fields)

    # with st.expander('Debug'):
    #     st.write(result_old)
    #     st.write(result_new)


def main():
    # Prep working directory
    TMP_WORKING_DIR.mkdir(exist_ok=True)

    _, col_center, _ = st.columns([1, 2, 1])

    with col_center:

        st.header("Zeek Schema Comparison")
        st.write("Static ZeekScript source code analyzer. Determines which log streams are exported and generates their schemas. Compare two versions to highlight changes.")

        with st.spinner("Setting things up..."):
            # Clone repository if not already done
            if TMP_WORKING_DIR.is_dir() and len(list(TMP_WORKING_DIR.glob("*"))) > 0:
                repo: Repo = Repo(TMP_WORKING_DIR)
            else:
                repo: Repo = Repo.clone_from(ZEEK_REPO_URL, TMP_WORKING_DIR)

            # Get list of unique versions
            zeek_versions_set = {t.name for t in repo.tags}
            zeek_versions = sorted(zeek_versions_set, reverse=True)

        with st.form("version_select_form"):

            compare_fields = {}

            version_select_left, version_select_right = st.columns([1, 1])
            with version_select_left:
                v_old = st.selectbox("Select versions to compare", options=zeek_versions, key="zeek_version_old", index=zeek_versions.index('v6.0.4'))
                custom_scripts_old = st.file_uploader("Add custom scripts (optional)", type=['zip'], accept_multiple_files=True, key="custom_scripts_old")

            with version_select_right:
                v_new = st.selectbox("New", label_visibility='hidden', options=zeek_versions, key="zeek_version_new", index=zeek_versions.index('v7.1.0'))
                custom_scripts_new = st.file_uploader("Add custom scripts (optional)", label_visibility="hidden", type=['zip'], accept_multiple_files=True, key="custom_scripts_new")

            _, c2, _ = st.columns([2, 3, 2])
            with c2:
                compare_fields['meta.filename'] = st.checkbox("Also highlight fields whose source file has changed", value=True)
                submitted = st.form_submit_button("Compare &rsaquo;", use_container_width=True)

            # st.markdown("<style>.stCheckbox {margin-top: -7px;margin-bottom: -7px;}</style>", unsafe_allow_html=True)

    if version.parse(v_old) < version.parse('v2.6') or version.parse(v_new) < version.parse('v2.6'):
        st.error("Bro releases prior to **v2.6.0** are unsupported.", icon="😕")
        return

    # submitted = True

    old = {
        'tag': v_old,
        'custom_scripts': custom_scripts_old
    }

    new = {
        'tag': v_new,
        'custom_scripts': custom_scripts_new
    }

    if submitted:
        st.markdown("<br><br>", unsafe_allow_html=True)
        generate_report(repo, old, new, compare_fields)


if __name__ == "__main__":
    main()
