import streamlit as st

from ui.api_client import get, post

st.title("Programs")

st.subheader("Create Program")

with st.form("create_program_form"):
    name = st.text_input("Name *")
    platform = st.text_input("Platform")
    scope_text = st.text_area("Scope")
    notes = st.text_area("Notes")
    submitted = st.form_submit_button("Create")

if submitted:
    if not name:
        st.error("Name is required.")
    else:
        try:
            post(
                "/programs",
                {
                    "name": name,
                    "platform": platform or None,
                    "scope_text": scope_text or None,
                    "notes": notes or None,
                },
            )
            st.success(f"Program '{name}' created successfully.")
        except Exception as exc:
            st.error(f"Failed to create program: {exc}")

st.subheader("All Programs")

try:
    programs = get("/programs")
    if programs:
        st.dataframe(programs, use_container_width=True)
    else:
        st.info("No programs found. Create one above.")
except Exception as exc:
    st.error(f"Failed to load programs: {exc}")
