import requests
import streamlit as st
import pandas as pd
from scanner import scan_folder

# 🔧 Page config (MUST be first Streamlit command)
st.set_page_config(
    page_title="Suspicious File Detector",
    page_icon="🛡️",
    layout="wide"
)

# 🎨 Styling
st.markdown("""
<style>
.block-container {padding-top: 2rem;}
h1 {text-align: center;}
</style>
""", unsafe_allow_html=True)

# 🧠 Title
st.markdown("<h1>🛡️ Suspicious File Detector</h1>", unsafe_allow_html=True)
st.markdown("### 🔍 Scan files and detect potential threats using VirusTotal")

# 🔐 VirusTotal function
def check_virustotal(file_hash, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        return data["data"]["attributes"]["last_analysis_stats"]
    else:
        return None


# =========================
# 📂 Folder Scan Section
# =========================

st.subheader("📁 Scan Folder")

folder = st.text_input("Enter folder path to scan")

if st.button("Scan Folder"):
    if folder:
        with st.spinner("Scanning files..."):
            data = scan_folder(folder)
            df = pd.DataFrame(data)

        st.success("Scan Completed ✅")

        st.write("📊 Scan Results")
        st.dataframe(df)

        suspicious_files = df[df["suspicious"] == True]

        st.write("⚠️ Suspicious Files")
        st.dataframe(suspicious_files)

        # 📥 Download report
        st.download_button(
            "📥 Download Report",
            df.to_csv(index=False),
            file_name="scan_report.csv"
        )
    else:
        st.warning("Please enter a folder path")


# =========================
# 📂 File Upload Section
# =========================

st.subheader("📂 Upload a File to Scan")

uploaded_file = st.file_uploader("Choose a file")

if uploaded_file is not None:
    import hashlib

    file_bytes = uploaded_file.read()
    file_hash = hashlib.sha256(file_bytes).hexdigest()

    st.write("📄 File Name:", uploaded_file.name)
    st.write("🔑 SHA256 Hash:", file_hash)

    # 🔍 Extension check
    ext = "." + uploaded_file.name.split(".")[-1]
    suspicious_ext = ext in [".exe", ".bat", ".ps1", ".vbs"]

    if suspicious_ext:
        st.error("⚠️ Suspicious File Detected (by extension)")
    else:
        st.success("✅ File looks safe (basic check)")

    # =========================
    # 🔥 VirusTotal Check
    # =========================

    api_key = st.secrets["VIRUSTOTAL_API_KEY"]

    with st.spinner("Checking VirusTotal..."):
        vt_result = check_virustotal(file_hash, api_key)

    if vt_result:
        malicious = vt_result.get("malicious", 0)
        harmless = vt_result.get("harmless", 0)

        st.write("🛡️ VirusTotal Analysis")

        col1, col2 = st.columns(2)
        col1.metric("🚨 Malicious", malicious)
        col2.metric("✅ Harmless", harmless)

        if malicious > 0:
            st.error("🚨 File is MALICIOUS!")
        else:
            st.success("✅ File appears safe (VirusTotal)")
    else:
        st.warning("No VirusTotal report found for this file")


# =========================
# ℹ️ Info Section
# =========================

with st.expander("ℹ️ How this works"):
    st.write("""
    - Generates SHA256 hash of the file
    - Checks suspicious file extensions
    - Queries VirusTotal API
    - Displays malware detection results
    """)