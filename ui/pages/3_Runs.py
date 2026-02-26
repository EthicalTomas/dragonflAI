import time

import streamlit as st

from ui.api_client import get, post

st.title("Runs")

try:
    targets = get("/targets")
except Exception as exc:
    st.error(f"Failed to load targets: {exc}")
    st.stop()

if not targets:
    st.warning("No targets found. Create a target first.")
    st.stop()

target_options = {t["name"]: t["id"] for t in targets}

st.subheader("Launch a Run")

selected_target = st.selectbox("Target", options=list(target_options.keys()))

if st.button("Start run"):
    try:
        result = post(
            "/runs",
            {"target_id": target_options[selected_target], "modules": ["dummy"]},
        )
        st.session_state["run_id"] = result["id"]
        st.success(f"Run {result['id']} started.")
    except Exception as exc:
        st.error(f"Failed to start run: {exc}")

if "run_id" in st.session_state:
    run_id = st.session_state["run_id"]
    st.subheader(f"Monitoring Run #{run_id}")

    placeholder = st.empty()
    terminal_statuses = {"succeeded", "failed", "cancelled"}

    for _ in range(120):
        try:
            run = get(f"/runs/{run_id}")
        except Exception as exc:
            placeholder.error(f"Failed to fetch run status: {exc}")
            break

        with placeholder.container():
            st.write(f"**Status:** {run['status']}")
            st.progress(int(run["progress"]) / 100)
            st.text_area("Logs", value=run.get("log_text", ""), height=200, disabled=True)

        if run["status"] in terminal_statuses:
            break

        time.sleep(1)
