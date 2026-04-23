import requests
import streamlit as st
import pandas as pd
from scanner import scan_folder

st.title("🛡️ Suspicious File Detector")

folder = st.text_input("Enter folder path to scan")

if st.button("Scan"):
    if folder:
        data = scan_folder(folder)
        df = pd.DataFrame(data)

        st.write("Scan Results")
        st.dataframe(df)

        suspicious_files = df[df["suspicious"] == True]

        st.write("⚠️ Suspicious Files")
        st.dataframe(suspicious_files)
    else:
        st.warning("Please enter a folder path")



st.header("📂 Upload a file to scan")

uploaded_file = st.file_uploader("Choose a file")

if uploaded_file is not None:
    import hashlib

    file_bytes = uploaded_file.read()
    file_hash = hashlib.sha256(file_bytes).hexdigest()

    st.write("File Name:", uploaded_file.name)
    st.write("SHA256 Hash:", file_hash)

    # Check extension
    ext = "." + uploaded_file.name.split(".")[-1]
    suspicious_ext = ext in [".exe", ".bat", ".ps1", ".vbs"]

    if suspicious_ext:
        st.error("⚠️ Suspicious File Detected (by extension)")
    else:
        st.success("✅ File looks safe (basic check)")

    # 🔥 VirusTotal check (move here)
    api_key = st.secrets["VIRUSTOTAL_API_KEY"]

    def check_virustotal(file_hash, api_key):
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": api_key}

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            return data["data"]["attributes"]["last_analysis_stats"]
        else:
            return None

    vt_result = check_virustotal(file_hash, api_key)

    if vt_result:
        malicious = vt_result.get("malicious", 0)
        harmless = vt_result.get("harmless", 0)

        st.write("🛡️ VirusTotal Result:")
        st.write(f"Malicious: {malicious}")
        st.write(f"Harmless: {harmless}")

        if malicious > 0:
            st.error("🚨 File is MALICIOUS!")
        else:
            st.success("✅ File appears safe (VirusTotal)")
    else:
        st.warning("No VirusTotal report found for this file")