import streamlit as st
import json
import sqlite3
from datetime import datetime
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from typing import Dict, List, Any
import uuid

# Initialize database
def init_db():
    conn = sqlite3.connect('threat_model.db', check_same_thread=False)
    c = conn.cursor()
    
    # Create tables
    c.execute('''
        CREATE TABLE IF NOT EXISTS iterations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            created_date TEXT,
            data TEXT
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS threats (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            severity TEXT,
            domain TEXT,
            created_date TEXT
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS mitigations (
            id TEXT PRIMARY KEY,
            threat_id TEXT,
            name TEXT NOT NULL,
            description TEXT,
            status TEXT,
            domain TEXT,
            created_date TEXT,
            FOREIGN KEY (threat_id) REFERENCES threats (id)
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS subdomains (
            id TEXT PRIMARY KEY,
            parent_domain TEXT,
            name TEXT NOT NULL,
            description TEXT,
            created_date TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

# Database operations
def get_db_connection():
    return sqlite3.connect('threat_model.db', check_same_thread=False)

def save_iteration(name: str, description: str, data: Dict):
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute('''
            INSERT OR REPLACE INTO iterations (name, description, created_date, data)
            VALUES (?, ?, ?, ?)
        ''', (name, description, datetime.now().isoformat(), json.dumps(data)))
        conn.commit()
        return True
    except Exception as e:
        st.error(f"Error saving iteration: {e}")
        return False
    finally:
        conn.close()

def load_iteration(name: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT data FROM iterations WHERE name = ?', (name,))
    result = c.fetchone()
    conn.close()
    if result:
        return json.loads(result[0])
    return None

def get_all_iterations():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT name, description, created_date FROM iterations ORDER BY created_date DESC')
    results = c.fetchall()
    conn.close()
    return results

def save_threat(threat_id: str, name: str, description: str, severity: str, domain: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO threats (id, name, description, severity, domain, created_date)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (threat_id, name, description, severity, domain, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def save_mitigation(mit_id: str, threat_id: str, name: str, description: str, status: str, domain: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO mitigations (id, threat_id, name, description, status, domain, created_date)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (mit_id, threat_id, name, description, status, domain, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_all_threats():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM threats ORDER BY id')
    results = c.fetchall()
    conn.close()
    return results

def get_mitigations_for_threat(threat_id: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM mitigations WHERE threat_id = ? ORDER BY id', (threat_id,))
    results = c.fetchall()
    conn.close()
    return results

def get_all_mitigations():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        SELECT m.*, t.name as threat_name 
        FROM mitigations m 
        LEFT JOIN threats t ON m.threat_id = t.id 
        ORDER BY m.id
    ''')
    results = c.fetchall()
    conn.close()
    return results

def delete_threat(threat_id: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('DELETE FROM mitigations WHERE threat_id = ?', (threat_id,))
    c.execute('DELETE FROM threats WHERE id = ?', (threat_id,))
    conn.commit()
    conn.close()

def delete_mitigation(mit_id: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('DELETE FROM mitigations WHERE id = ?', (mit_id,))
    conn.commit()
    conn.close()

def save_subdomain(subdomain_id: str, parent_domain: str, name: str, description: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO subdomains (id, parent_domain, name, description, created_date)
        VALUES (?, ?, ?, ?, ?)
    ''', (subdomain_id, parent_domain, name, description, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_subdomains(parent_domain: str = None):
    conn = get_db_connection()
    c = conn.cursor()
    if parent_domain:
        c.execute('SELECT * FROM subdomains WHERE parent_domain = ? ORDER BY name', (parent_domain,))
    else:
        c.execute('SELECT * FROM subdomains ORDER BY parent_domain, name')
    results = c.fetchall()
    conn.close()
    return results

# Static domain definitions
STATIC_DOMAINS = {
    "Physical Domain": {
        "color": "#FFE4B5",
        "position": {"x": 0.85, "y": 0.8},
        "components": ["Facilities", "Hardware", "Infrastructure"]
    },
    "Logical Domain": {
        "color": "#E6F3FF",
        "position": {"x": 0.85, "y": 0.6},
        "components": ["Network", "Platform", "Applications"]
    },
    "Business Value": {
        "color": "#F0E6FF",
        "position": {"x": 0.3, "y": 0.9},
        "components": ["Financial Value", "Social Impact"]
    },
    "Services": {
        "color": "#FFE6F0",
        "position": {"x": 0.3, "y": 0.7},
        "components": ["Customer Services", "Internal Services"]
    },
    "People": {
        "color": "#E6FFE6",
        "position": {"x": 0.2, "y": 0.5},
        "components": ["Employees", "Contractors", "Partners"]
    },
    "Processes": {
        "color": "#FFFFE6",
        "position": {"x": 0.4, "y": 0.5},
        "components": ["Business Processes", "IT Processes"]
    },
    "Information": {
        "color": "#E6FFFF",
        "position": {"x": 0.6, "y": 0.6},
        "components": ["Data", "Documents", "Knowledge"]
    },
    "Information Technology": {
        "color": "#F5F5DC",
        "position": {"x": 0.4, "y": 0.3},
        "components": ["Applications", "Platform", "Network", "Data"]
    },
    "Customer": {
        "color": "#FFF0F5",
        "position": {"x": 0.1, "y": 0.7},
        "components": ["End Users", "Business Users"]
    }
}

STATIC_INTERACTIONS = [
    {"from": "Customer", "to": "Services", "relationship": "request"},
    {"from": "Services", "to": "Financial Value", "relationship": "create"},
    {"from": "Services", "to": "Information", "relationship": "expose/manipulate"},
    {"from": "People", "to": "Services", "relationship": "build"},
    {"from": "People", "to": "Processes", "relationship": "support"},
    {"from": "Processes", "to": "Information", "relationship": "connect"},
    {"from": "Information Technology", "to": "Information", "relationship": "host"},
    {"from": "Information Technology", "to": "Physical Domain", "relationship": "host"},
    {"from": "Information", "to": "Physical Domain", "relationship": "transfer"},
    {"from": "Physical Domain", "to": "Logical Domain", "relationship": "represent"}
]

def initialize_session_state():
    if 'current_iteration' not in st.session_state:
        st.session_state.current_iteration = None
    if 'domains' not in st.session_state:
        st.session_state.domains = STATIC_DOMAINS.copy()
    if 'interactions' not in st.session_state:
        st.session_state.interactions = STATIC_INTERACTIONS.copy()
    if 'selected_threats' not in st.session_state:
        st.session_state.selected_threats = {}
    if 'selected_mitigations' not in st.session_state:
        st.session_state.selected_mitigations = {}

def render_architecture_diagram():
    fig = go.Figure()
    
    # Add domains
    for domain_name, domain_info in st.session_state.domains.items():
        fig.add_trace(go.Scatter(
            x=[domain_info["position"]["x"]],
            y=[domain_info["position"]["y"]],
            mode='markers+text',
            marker=dict(
                size=100,
                color=domain_info["color"],
                line=dict(color='black', width=2)
            ),
            text=domain_name,
            textposition='middle center',
            name=domain_name,
            showlegend=False
        ))
    
    # Add interactions
    for interaction in st.session_state.interactions:
        from_domain = st.session_state.domains.get(interaction["from"])
        to_domain = st.session_state.domains.get(interaction["to"])
        
        if from_domain and to_domain:
            fig.add_trace(go.Scatter(
                x=[from_domain["position"]["x"], to_domain["position"]["x"]],
                y=[from_domain["position"]["y"], to_domain["position"]["y"]],
                mode='lines+text',
                line=dict(color='gray', width=2),
                text=['', f'<<{interaction["relationship"]}>>'],
                textposition='middle center',
                showlegend=False,
                name=f'{interaction["from"]} -> {interaction["to"]}'
            ))
    
    fig.update_layout(
        title="Threat Model Architecture Diagram",
        showlegend=False,
        height=600,
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        plot_bgcolor='white'
    )
    
    return fig

def admin_panel():
    st.header("🔧 Admin Panel")
    
    tab1, tab2, tab3, tab4 = st.tabs(["Threats", "Mitigations", "Subdomains", "Iterations"])
    
    with tab1:
        st.subheader("Manage Threats")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Create New Threat**")
            with st.form("create_threat"):
                threat_id = st.text_input("Threat ID (e.g., ADV001)", key="new_threat_id")
                threat_name = st.text_input("Threat Name", key="new_threat_name")
                threat_desc = st.text_area("Description", key="new_threat_desc")
                severity = st.selectbox("Severity", ["Low", "Medium", "High", "Critical"], key="new_threat_severity")
                domain = st.selectbox("Primary Domain", list(STATIC_DOMAINS.keys()), key="new_threat_domain")
                
                if st.form_submit_button("Create Threat"):
                    if threat_id and threat_name:
                        save_threat(threat_id, threat_name, threat_desc, severity, domain)
                        st.success(f"Threat {threat_id} created successfully!")
                        st.rerun()
        
        with col2:
            st.write("**Existing Threats**")
            threats = get_all_threats()
            if threats:
                threat_df = pd.DataFrame(threats, columns=['ID', 'Name', 'Description', 'Severity', 'Domain', 'Created'])
                st.dataframe(threat_df, use_container_width=True)
                
                threat_to_delete = st.selectbox("Delete Threat", [""] + [t[0] for t in threats])
                if st.button("Delete Selected Threat") and threat_to_delete:
                    delete_threat(threat_to_delete)
                    st.success(f"Threat {threat_to_delete} deleted!")
                    st.rerun()
    
    with tab2:
        st.subheader("Manage Mitigations")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Create New Mitigation**")
            threats = get_all_threats()
            if threats:
                with st.form("create_mitigation"):
                    mit_id = st.text_input("Mitigation ID (e.g., MIT001)", key="new_mit_id")
                    threat_id = st.selectbox("For Threat", [t[0] for t in threats], key="new_mit_threat")
                    mit_name = st.text_input("Mitigation Name", key="new_mit_name")
                    mit_desc = st.text_area("Description", key="new_mit_desc")
                    status = st.selectbox("Status", ["Planned", "In Progress", "Implemented", "Verified"], key="new_mit_status")
                    domain = st.selectbox("Implementation Domain", list(STATIC_DOMAINS.keys()), key="new_mit_domain")
                    
                    if st.form_submit_button("Create Mitigation"):
                        if mit_id and mit_name and threat_id:
                            save_mitigation(mit_id, threat_id, mit_name, mit_desc, status, domain)
                            st.success(f"Mitigation {mit_id} created successfully!")
                            st.rerun()
            else:
                st.info("Create threats first before adding mitigations.")
        
        with col2:
            st.write("**Existing Mitigations**")
            mitigations = get_all_mitigations()
            if mitigations:
                mit_df = pd.DataFrame(mitigations, columns=['ID', 'Threat_ID', 'Name', 'Description', 'Status', 'Domain', 'Created', 'Threat_Name'])
                st.dataframe(mit_df[['ID', 'Threat_ID', 'Name', 'Status', 'Domain', 'Threat_Name']], use_container_width=True)
                
                mit_to_delete = st.selectbox("Delete Mitigation", [""] + [m[0] for m in mitigations])
                if st.button("Delete Selected Mitigation") and mit_to_delete:
                    delete_mitigation(mit_to_delete)
                    st.success(f"Mitigation {mit_to_delete} deleted!")
                    st.rerun()
    
    with tab3:
        st.subheader("Manage Subdomains")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Create New Subdomain**")
            with st.form("create_subdomain"):
                subdomain_id = st.text_input("Subdomain ID", key="new_subdomain_id")
                parent_domain = st.selectbox("Parent Domain", list(STATIC_DOMAINS.keys()), key="new_subdomain_parent")
                subdomain_name = st.text_input("Subdomain Name", key="new_subdomain_name")
                subdomain_desc = st.text_area("Description", key="new_subdomain_desc")
                
                if st.form_submit_button("Create Subdomain"):
                    if subdomain_id and subdomain_name and parent_domain:
                        save_subdomain(subdomain_id, parent_domain, subdomain_name, subdomain_desc)
                        st.success(f"Subdomain {subdomain_name} created successfully!")
                        st.rerun()
        
        with col2:
            st.write("**Existing Subdomains**")
            subdomains = get_subdomains()
            if subdomains:
                subdomain_df = pd.DataFrame(subdomains, columns=['ID', 'Parent_Domain', 'Name', 'Description', 'Created'])
                st.dataframe(subdomain_df, use_container_width=True)
    
    with tab4:
        st.subheader("Manage Iterations")
        
        iterations = get_all_iterations()
        if iterations:
            iter_df = pd.DataFrame(iterations, columns=['Name', 'Description', 'Created'])
            st.dataframe(iter_df, use_container_width=True)
            
            # Save current state as new iteration
            with st.form("save_iteration"):
                iteration_name = st.text_input("Iteration Name")
                iteration_desc = st.text_area("Description")
                
                if st.form_submit_button("Save Current State as Iteration"):
                    if iteration_name:
                        data = {
                            'domains': st.session_state.domains,
                            'interactions': st.session_state.interactions,
                            'selected_threats': st.session_state.selected_threats,
                            'selected_mitigations': st.session_state.selected_mitigations
                        }
                        if save_iteration(iteration_name, iteration_desc, data):
                            st.success(f"Iteration '{iteration_name}' saved successfully!")
                            st.rerun()

def user_interface():
    st.header("🎯 Threat Modeling Interface")
    
    # Load iteration selector
    iterations = get_all_iterations()
    if iterations:
        col1, col2 = st.columns([2, 1])
        
        with col1:
            selected_iteration = st.selectbox(
                "Load Iteration",
                ["New Iteration"] + [iter[0] for iter in iterations],
                key="iteration_selector"
            )
        
        with col2:
            if st.button("Load Selected Iteration") and selected_iteration != "New Iteration":
                data = load_iteration(selected_iteration)
                if data:
                    st.session_state.domains = data.get('domains', STATIC_DOMAINS.copy())
                    st.session_state.interactions = data.get('interactions', STATIC_INTERACTIONS.copy())
                    st.session_state.selected_threats = data.get('selected_threats', {})
                    st.session_state.selected_mitigations = data.get('selected_mitigations', {})
                    st.session_state.current_iteration = selected_iteration
                    st.success(f"Loaded iteration: {selected_iteration}")
                    st.rerun()
    
    # Display current iteration info
    if st.session_state.current_iteration:
        st.info(f"Current Iteration: **{st.session_state.current_iteration}**")
    
    # Main interface tabs
    tab1, tab2, tab3 = st.tabs(["Architecture View", "Threat Selection", "Analysis"])
    
    with tab1:
        st.subheader("Architecture Diagram")
        
        # Display the interactive diagram
        fig = render_architecture_diagram()
        st.plotly_chart(fig, use_container_width=True)
        
        # Interaction management
        st.subheader("Manage Interactions")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Current Interactions**")
            if st.session_state.interactions:
                for i, interaction in enumerate(st.session_state.interactions):
                    col_a, col_b = st.columns([3, 1])
                    with col_a:
                        st.write(f"{interaction['from']} → {interaction['to']} ({interaction['relationship']})")
                    with col_b:
                        if st.button("Delete", key=f"del_int_{i}"):
                            st.session_state.interactions.pop(i)
                            st.rerun()
        
        with col2:
            st.write("**Add New Interaction**")
            with st.form("add_interaction"):
                from_domain = st.selectbox("From Domain", list(st.session_state.domains.keys()))
                to_domain = st.selectbox("To Domain", list(st.session_state.domains.keys()))
                relationship = st.text_input("Relationship (e.g., uses, creates, hosts)")
                
                if st.form_submit_button("Add Interaction"):
                    if from_domain != to_domain and relationship:
                        new_interaction = {
                            "from": from_domain,
                            "to": to_domain,
                            "relationship": relationship
                        }
                        st.session_state.interactions.append(new_interaction)
                        st.rerun()
    
    with tab2:
        st.subheader("Select Threats and Mitigations")
        
        threats = get_all_threats()
        if not threats:
            st.warning("No threats available. Please create threats in the Admin Panel first.")
            return
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Available Threats**")
            for threat in threats:
                threat_id, name, desc, severity, domain, created = threat
                
                is_selected = st.checkbox(
                    f"**{threat_id}**: {name}",
                    key=f"threat_{threat_id}",
                    value=threat_id in st.session_state.selected_threats
                )
                
                if is_selected and threat_id not in st.session_state.selected_threats:
                    st.session_state.selected_threats[threat_id] = threat
                elif not is_selected and threat_id in st.session_state.selected_threats:
                    del st.session_state.selected_threats[threat_id]
                    # Also remove associated mitigations
                    st.session_state.selected_mitigations = {
                        k: v for k, v in st.session_state.selected_mitigations.items()
                        if v[1] != threat_id
                    }
                
                if is_selected:
                    st.write(f"   📊 **Severity**: {severity} | 🏢 **Domain**: {domain}")
                    if desc:
                        st.write(f"   📝 {desc}")
        
        with col2:
            st.write("**Select Mitigations for Selected Threats**")
            
            for threat_id in st.session_state.selected_threats:
                st.write(f"**Mitigations for {threat_id}:**")
                mitigations = get_mitigations_for_threat(threat_id)
                
                if mitigations:
                    for mitigation in mitigations:
                        mit_id, t_id, name, desc, status, domain, created = mitigation
                        
                        is_selected = st.checkbox(
                            f"  {mit_id}: {name} ({status})",
                            key=f"mit_{mit_id}",
                            value=mit_id in st.session_state.selected_mitigations
                        )
                        
                        if is_selected:
                            st.session_state.selected_mitigations[mit_id] = mitigation
                        elif mit_id in st.session_state.selected_mitigations:
                            del st.session_state.selected_mitigations[mit_id]
                        
                        if is_selected and desc:
                            st.write(f"     📝 {desc}")
                else:
                    st.write("   ⚠️ No mitigations available for this threat")
    
    with tab3:
        st.subheader("Analysis Dashboard")
        
        if st.session_state.selected_threats:
            # Threat overview
            st.write("### Selected Threats Overview")
            
            threat_data = []
            for threat_id, threat in st.session_state.selected_threats.items():
                mitigations_count = len([m for m in st.session_state.selected_mitigations.values() if m[1] == threat_id])
                threat_data.append({
                    'Threat ID': threat_id,
                    'Name': threat[1],
                    'Severity': threat[3],
                    'Domain': threat[4],
                    'Mitigations': mitigations_count
                })
            
            threat_df = pd.DataFrame(threat_data)
            st.dataframe(threat_df, use_container_width=True)
            
            # Charts
            col1, col2 = st.columns(2)
            
            with col1:
                if len(threat_data) > 0:
                    severity_count = threat_df['Severity'].value_counts()
                    fig_severity = px.pie(
                        values=severity_count.values,
                        names=severity_count.index,
                        title="Threats by Severity"
                    )
                    st.plotly_chart(fig_severity, use_container_width=True)
            
            with col2:
                if len(threat_data) > 0:
                    domain_count = threat_df['Domain'].value_counts()
                    fig_domain = px.bar(
                        x=domain_count.index,
                        y=domain_count.values,
                        title="Threats by Domain"
                    )
                    st.plotly_chart(fig_domain, use_container_width=True)
            
            # Mitigation status
            if st.session_state.selected_mitigations:
                st.write("### Mitigation Status")
                mit_data = []
                for mit_id, mitigation in st.session_state.selected_mitigations.items():
                    mit_data.append({
                        'Mitigation ID': mit_id,
                        'Threat ID': mitigation[1],
                        'Name': mitigation[2],
                        'Status': mitigation[4],
                        'Domain': mitigation[5]
                    })
                
                mit_df = pd.DataFrame(mit_data)
                st.dataframe(mit_df, use_container_width=True)
                
                # Mitigation status chart
                status_count = mit_df['Status'].value_counts()
                fig_status = px.bar(
                    x=status_count.index,
                    y=status_count.values,
                    title="Mitigations by Status"
                )
                st.plotly_chart(fig_status, use_container_width=True)
        else:
            st.info("Select threats and mitigations to see analysis.")

def main():
    st.set_page_config(
        page_title="Threat Modeling System",
        page_icon="🛡️",
        layout="wide"
    )
    
    # Initialize database and session state
    init_db()
    initialize_session_state()
    
    st.title("🛡️ Threat Modeling Architecture System")
    st.markdown("---")
    
    # Sidebar for navigation
    with st.sidebar:
        st.header("Navigation")
        mode = st.radio(
            "Select Mode:",
            ["👥 User Interface", "🔧 Admin Panel"],
            index=0
        )
        
        st.markdown("---")
        st.header("Quick Stats")
        
        # Display quick statistics
        threats = get_all_threats()
        mitigations = get_all_mitigations()
        iterations = get_all_iterations()
        
        st.metric("Total Threats", len(threats))
        st.metric("Total Mitigations", len(mitigations))
        st.metric("Saved Iterations", len(iterations))
        
        if st.session_state.selected_threats:
            st.metric("Selected Threats", len(st.session_state.selected_threats))
        if st.session_state.selected_mitigations:
            st.metric("Selected Mitigations", len(st.session_state.selected_mitigations))
    
    # Main content based on mode
    if mode == "🔧 Admin Panel":
        admin_panel()
    else:
        user_interface()

if __name__ == "__main__":
    main()
