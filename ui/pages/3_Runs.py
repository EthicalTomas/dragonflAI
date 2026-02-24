import os
import sys

import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import api_client as client  # noqa: E402

st.title("Runs")

with st.expander("Launch Run"):
    program_id = st.number_input("Program ID", min_value=1, step=1)
    if st.button("Launch"):
        try:
            run = client.create_run(int(program_id))
            st.success(f"Launched run #{run['id']} — status: {run['status']}")
        except Exception as e:
            st.error(str(e))

st.subheader("All Runs")
try:
    runs = client.list_runs()
    if runs:
        st.table(runs)
    else:
        st.info("No runs yet.")
except Exception as e:
    st.error(str(e))
