import streamlit as st

from ui.api_client import get, post

st.title("Targets")

try:
    programs = get("/programs")
except Exception as exc:
    st.error(f"Failed to load programs: {exc}")
    st.stop()

if not programs:
    st.warning("No programs found. Create a program first.")
    st.stop()

program_options = {p["name"]: p["id"] for p in programs}

st.subheader("Create Target")

with st.form("create_target_form"):
    selected_program = st.selectbox("Program *", options=list(program_options.keys()))
    name = st.text_input("Name *")
    roots_text = st.text_area("Roots * (one per line)")
    tags_text = st.text_input("Tags (comma-separated)")
    submitted = st.form_submit_button("Create")

if submitted:
    roots = [r.strip() for r in roots_text.splitlines() if r.strip()]
    tags = [t.strip() for t in tags_text.split(",") if t.strip()]
    if not name:
        st.error("Name is required.")
    elif not roots:
        st.error("At least one root is required.")
    else:
        try:
            post(
                "/targets",
                {
                    "program_id": program_options[selected_program],
                    "name": name,
                    "roots": roots,
                    "tags": tags,
                },
            )
            st.success(f"Target '{name}' created successfully.")
        except Exception as exc:
            st.error(f"Failed to create target: {exc}")

st.subheader("All Targets")

try:
    targets = get("/targets")
    if targets:
        st.dataframe(targets, use_container_width=True)
    else:
        st.info("No targets found. Create one above.")
except Exception as exc:
    st.error(f"Failed to load targets: {exc}")
