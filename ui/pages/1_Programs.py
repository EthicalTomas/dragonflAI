import os
import sys

import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import api_client as client  # noqa: E402

st.title("Programs")

with st.expander("Create Program"):
    name = st.text_input("Name")
    platform = st.text_input("Platform (e.g. HackerOne)")
    scope_raw = st.text_area("Scope (one rule per line)")
    if st.button("Create"):
        try:
            prog = client.create_program(name, platform, scope_raw)
            st.success(f"Created program #{prog['id']}: {prog['name']}")
        except Exception as e:
            st.error(str(e))

st.subheader("All Programs")
try:
    programs = client.list_programs()
    if programs:
        st.table(programs)
    else:
        st.info("No programs yet.")
except Exception as e:
    st.error(str(e))
