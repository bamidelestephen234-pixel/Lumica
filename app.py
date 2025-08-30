import streamlit as st

# Start with basic working app
st.title("Akin's Sunrise School System")
st.success("App is working correctly!")

# Add working content
st.header("Welcome")
st.write("This is your working school management system.")

# Sidebar navigation
menu = st.sidebar.selectbox("Choose Section", ["Home", "Students", "Reports"])

if menu == "Home":
    st.write("Welcome to Akin's Sunrise School!")
elif menu == "Students":
    st.write("Student management section")
elif menu == "Reports":
    st.write("Report generation section")
