import os
import sys

import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import api_client as client  # noqa: E402

st.title("Targets")

with st.expander("Add Target"):
    program_id = st.number_input("Program ID", min_value=1, step=1)
    value = st.text_input("Value (domain / IP / URL)")
    kind = st.selectbox("Kind", ["domain", "ip", "url", "wildcard"])
    if st.button("Add"):
        try:
            tgt = client.create_target(int(program_id), value, kind)
            st.success(f"Added target #{tgt['id']}: {tgt['value']}")
        except Exception as e:
            st.error(str(e))

st.subheader("All Targets")
try:
    targets = client.list_targets()
    if targets:
        st.table(targets)
    else:
        st.info("No targets yet.")
except Exception as e:
    st.error(str(e))
