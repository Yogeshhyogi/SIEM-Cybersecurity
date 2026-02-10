import streamlit as st
import pandas as pd
import os
import plotly.express as px
from datetime import datetime, timedelta
import io

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="GSS SIEM - Global Threat SOC", layout="wide", page_icon="🛡️")

# --- ADVANCED CSS FOR DEEP BLACK BRANDING ---
st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    h1, h2, h3, .stHeader, [data-testid="stHeader"] {
        color: #000000 !important;
        font-weight: 800 !important;
    }
    [data-testid="stMetric"] {
        background-color: #ffffff !important; 
        border-radius: 10px; 
        padding: 15px; 
        border: 2px solid #000000;
        box-shadow: 2px 2px 10px rgba(0,0,0,0.5);
    }
    [data-testid="stMetricLabel"] p {
        color: #000000 !important;
        font-weight: 700 !important;
        font-size: 1.1rem !important;
    }
    [data-testid="stMetricValue"] div {
        color: #000000 !important;
        font-weight: 900 !important;
    }
    section[data-testid="stSidebar"] {
        background-color: #161b22;
        border-right: 1px solid #30363d;
    }
    .stButton>button {
        width: 100%;
        border-radius: 5px;
    }
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    hr { border-top: 2px solid #000000 !important; }
    </style>
    """, unsafe_allow_html=True)

# Paths
BASE_DB = os.path.join('database', 'events.csv')
INTEL_DB = os.path.join('database', 'intel_enriched.csv')

# --- SIDEBAR CONTROL PANEL ---
with st.sidebar:
    st.markdown('<h2 style="color: #ffffff !important;">🛡️ GSS Controls</h2>', unsafe_allow_html=True)
    st.info("System Management")
    
    if st.button("🚨 Wipe Database (Reset)"):
        for file in [BASE_DB, INTEL_DB]:
            if os.path.exists(file):
                try: os.remove(file)
                except: pass
        st.success("System Reset!")
        st.rerun()

# --- HEADER SECTION ---
st.markdown('<h1 style="text-align: center; color: #000000; font-size: 3rem;">🛡️ GATEWAY SOFTWARE SOLUTION SIEM (GSS)</h1>', unsafe_allow_html=True)

# --- DATA PROCESSING FRAGMENT ---
@st.fragment(run_every=2)
def run_dashboard():
    current_db = INTEL_DB if os.path.exists(INTEL_DB) else BASE_DB
    
    if os.path.exists(current_db):
        try:
            df = pd.read_csv(current_db)
            if not df.empty:
                df['Timestamp'] = pd.to_datetime(df['Timestamp'])
                
                # --- KPI ROW ---
                k1, k2, k3, k4 = st.columns(4)
                k1.metric("Total Log Volume", len(df))
                criticals = len(df[df['Risk_Level'] == 'High'])
                k2.metric("Critical Threats", criticals, delta=f"{criticals} Active", delta_color="inverse")
                k3.metric("Unique Attackers", df['Source_IP'].nunique())
                k4.metric("Attack Types", f"{df['Event'].nunique()} Vectors")

                st.markdown("---")

                # --- TREND & TOP ATTACKERS ---
                c1, c2 = st.columns([2, 1])
                with c1:
                    st.markdown('<h3 style="color: #000000;">📈 Attack Velocity</h3>', unsafe_allow_html=True)
                    last_hour = datetime.now() - timedelta(hours=1)
                    trend_df = df[df['Timestamp'] > last_hour].copy()
                    if not trend_df.empty:
                        trend_df = trend_df.set_index('Timestamp').resample('5T').size().reset_index(name='Count')
                        fig = px.line(trend_df, x='Timestamp', y='Count', template="plotly_dark", line_shape="spline", color_discrete_sequence=['#ff4b4b'])
                        fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
                        st.plotly_chart(fig, use_container_width=True)
                with c2:
                    st.markdown('<h3 style="color: #000000;">🕵️ Top IPs</h3>', unsafe_allow_html=True)
                    st.dataframe(df['Source_IP'].value_counts().head(10), use_container_width=True)

                # --- MAP & DISTRIBUTION ---
                st.markdown("---")
                m1, m2 = st.columns([1.5, 1])
                with m1:
                    st.markdown('<h3 style="color: #000000;">🌎 Global Threat Geo-Map</h3>', unsafe_allow_html=True)
                    map_df = df.dropna(subset=['Latitude', 'Longitude'])
                    if not map_df.empty:
                        fig_map = px.scatter_geo(map_df, lat='Latitude', lon='Longitude', color='Risk_Level', 
                                               projection="orthographic", template="plotly_dark", 
                                               color_discrete_map={'High': '#ff4b4b', 'Medium': '#ffa500', 'Low': '#00cc96'},
                                               hover_data=['Source_IP', 'Country', 'ISP_Owner'])
                        fig_map.update_layout(margin={"r":0,"t":0,"l":0,"b":0})
                        st.plotly_chart(fig_map, use_container_width=True)

                with m2:
                    st.markdown('<h3 style="color: #000000;">📊 Distribution</h3>', unsafe_allow_html=True)
                    fig_bar = px.bar(df['Event'].value_counts().reset_index(), x='count', y='Event', orientation='h', template="plotly_dark", color_discrete_sequence=['#ff4b4b'])
                    st.plotly_chart(fig_bar, use_container_width=True)

                # --- LIVE FEED HEADER & DOWNLOAD (SIDE BY SIDE) ---
                st.markdown("---")
                header_col, download_col = st.columns([2, 1], vertical_alignment="center")
                
                with header_col:
                    st.markdown('<h3 style="color: #000000; margin-bottom: 0;">📋 Live Threat Feed</h3>', unsafe_allow_html=True)
                
                with download_col:
                    # Excel buffer creation
                    buffer = io.BytesIO()
                    with pd.ExcelWriter(buffer, engine='xlsxwriter') as writer:
                        df.to_excel(writer, index=False, sheet_name='Live_Attacks')
                    
                    st.download_button(
                        label=f"📥 Download Log ({len(df)} Events)",
                        data=buffer.getvalue(),
                        file_name=f'GSS_SIEM_LOG_{datetime.now().strftime("%H%M")}.xlsx',
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        key="live_download_btn"
                    )

                def color_risk(val):
                    if val == 'High': return 'color: #ff4b4b; font-weight: bold;'
                    elif val == 'Medium': return 'color: #ffa500;'
                    return 'color: white;'
                
                st.dataframe(df.tail(15).sort_index(ascending=False).style.applymap(color_risk, subset=['Risk_Level']), use_container_width=True, hide_index=True)

            else:
                st.info("System Online. Waiting for logs...")
        except Exception as e:
            st.error(f"GSS Core Engine Error: {e}")
    else:
        st.warning("⚠️ Database Not Found. Ensure scripts are running.")

if __name__ == "__main__":
    run_dashboard()