import streamlit as st
import pandas as pd
import joblib
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
model = joblib.load(os.path.join(BASE_DIR, 'nids_model.pkl'))
model_columns = joblib.load(os.path.join(BASE_DIR, 'model_columns.pkl'))

st.set_page_config(page_title="NIDS - Network Intrusion Detection", layout="wide")

# --- Custom styling ---
st.markdown("""
    <style>
    .main-title {
        font-size: 3.2rem;
        font-weight: 800;
        text-align: left;
        margin-bottom: 0.2rem;
        letter-spacing: -0.5px;
    }
    .subtitle {
        text-align: left;
        color: #999;
        font-size: 1.05rem;
        margin-bottom: 2rem;
    }
    .stButton>button {
        width: 100%;
        background-color: #1f77b4;
        color: white;
        font-weight: 600;
        padding: 0.7rem;
        border-radius: 8px;
        border: none;
        font-size: 1rem;
    }
    .stButton>button:hover {
        background-color: #145a86;
    }
    .section-card {
        background-color: #161b22;
        border: 1px solid #2a2f38;
        border-radius: 12px;
        padding: 1.5rem 1.5rem 0.5rem 1.5rem;
        margin-bottom: 1rem;
    }
    .section-header {
        font-size: 1.3rem;
        font-weight: 700;
        margin-bottom: 1rem;
        border-bottom: 1px solid #2a2f38;
        padding-bottom: 0.6rem;
    }
    .result-box-attack {
        background-color: #2b1416;
        border: 1px solid #6e2530;
        border-radius: 10px;
        padding: 1.5rem;
        text-align: center;
    }
    .result-box-normal {
        background-color: #10261a;
        border: 1px solid #245c3b;
        border-radius: 10px;
        padding: 1.5rem;
        text-align: center;
    }
    .result-label-attack {
        color: #ff4b5c;
        font-size: 1.6rem;
        font-weight: 700;
    }
    .result-label-normal {
        color: #3dd68c;
        font-size: 1.6rem;
        font-weight: 700;
    }
    </style>
""", unsafe_allow_html=True)

# --- Header ---
st.markdown('<p class="main-title">Network Intrusion Detection System</p>', unsafe_allow_html=True)
st.markdown('<p class="subtitle">Machine learning based classification of live network traffic</p>', unsafe_allow_html=True)

# --- Top metrics row ---
m1, m2, m3, m4 = st.columns(4)
m1.metric("Model", "XGBoost")
m2.metric("CV Accuracy", "99.6%")
m3.metric("Dataset", "NSL-KDD")
m4.metric("Features Used", "41")

st.markdown("---")

# --- Layout: form on left, results on right ---
left, right = st.columns([1.2, 1])

with left:
    
    st.markdown('<p class="section-header">Connection Details</p>', unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["Basic Info", "Advanced Metrics"])

    with tab1:
        c1, c2 = st.columns(2)
        with c1:
            protocol_type = st.selectbox("Protocol Type", ["tcp", "udp", "icmp"])
            service = st.selectbox("Service", ["http", "ftp_data", "smtp", "private", "domain_u", "other"])
            flag = st.selectbox("Flag", ["SF", "S0", "REJ", "RSTR", "SH"])
        with c2:
            duration = st.number_input("Duration (sec)", min_value=0, value=0)
            src_bytes = st.number_input("Source Bytes", min_value=0, value=200)
            dst_bytes = st.number_input("Destination Bytes", min_value=0, value=8000)

    with tab2:
        c3, c4 = st.columns(2)
        with c3:
            count = st.number_input("Count (connections to host)", min_value=0, value=1)
            logged_in = st.selectbox("Logged In?", [1, 0])
        with c4:
            serror_rate = st.slider("Serror Rate", 0.0, 1.0, 0.0)
            same_srv_rate = st.slider("Same Service Rate", 0.0, 1.0, 1.0)

    st.write("")
    classify_clicked = st.button("Classify Traffic")

    with st.expander("Try a preset example"):
        p1, p2 = st.columns(2)
        with p1:
            st.caption("**Normal-looking traffic**")
            st.code("tcp · http · SF\nsrc=200 dst=8000\nlogged_in=1, serror=0.0")
        with p2:
            st.caption("**Attack-looking traffic**")
            st.code("tcp · private · S0\nsrc=0 dst=0, count=200\nlogged_in=0, serror=1.0")

    st.markdown('</div>', unsafe_allow_html=True)

with right:
    
    st.markdown('<p class="section-header">Result</p>', unsafe_allow_html=True)

    if classify_clicked:
        input_data = pd.DataFrame(0, index=[0], columns=model_columns)
        input_data['duration'] = duration
        input_data['src_bytes'] = src_bytes
        input_data['dst_bytes'] = dst_bytes
        input_data['count'] = count
        input_data['logged_in'] = logged_in
        input_data['serror_rate'] = serror_rate
        input_data['same_srv_rate'] = same_srv_rate

        protocol_map = {"tcp": 1, "udp": 2, "icmp": 0}
        flag_map = {"SF": 9, "S0": 5, "REJ": 4, "RSTR": 6, "SH": 8}
        input_data['protocol_type'] = protocol_map.get(protocol_type, 1)
        input_data['flag'] = flag_map.get(flag, 9)

        prediction = model.predict(input_data)[0]
        prediction_proba = model.predict_proba(input_data)[0]

        if prediction == 0:
            st.markdown(f"""
                <div class="result-box-attack">
                    <p class="result-label-attack">ATTACK DETECTED</p>
                </div>
            """, unsafe_allow_html=True)
            st.write("")
            st.progress(float(prediction_proba[0]))
            st.write(f"**Confidence: {prediction_proba[0]*100:.1f}%**")
        else:
            st.markdown(f"""
                <div class="result-box-normal">
                    <p class="result-label-normal">NORMAL TRAFFIC</p>
                </div>
            """, unsafe_allow_html=True)
            st.write("")
            st.progress(float(prediction_proba[1]))
            st.write(f"**Confidence: {prediction_proba[1]*100:.1f}%**")

        with st.expander("Show raw prediction probabilities"):
            st.write({
                "Attack probability": f"{prediction_proba[0]*100:.2f}%",
                "Normal probability": f"{prediction_proba[1]*100:.2f}%"
            })
    else:
        st.info("Fill in the connection details and click Classify Traffic to see a prediction here.")

    st.markdown('</div>', unsafe_allow_html=True)

st.markdown("---")
st.caption("Built with XGBoost trained on the NSL-KDD dataset · Cross-validated accuracy: 99.6%")