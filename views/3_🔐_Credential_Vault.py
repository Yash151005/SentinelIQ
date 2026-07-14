"""
SentinelIQ — Page 3: Quantum-Proof Credential Vault
=====================================================
- PQC vault table with encryption metadata
- Quantum Shield badges per credential
- Key generation and rotation UI
- Encryption/decryption demo panel
"""

import streamlit as st
import plotly.graph_objects as go
import pandas as pd
import datetime
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from utils import mongo_client, pqc_vault, data_simulator

st.set_page_config(page_title="SentinelIQ — Credential Vault", page_icon="🔐", layout="wide")

if not st.session_state.get("authenticated"):
    st.warning("🔒 Please login from the main page.")
    st.stop()

from utils import rbac_engine

if not rbac_engine.check_page_permission(st.session_state.get("role"), "Credential_Vault"):
    st.error("❌ Access Denied: You do not have permission to view the Credential Vault.")
    st.stop()

if "initialized" not in st.session_state:
    data_simulator.seed_database()
    st.session_state["initialized"] = True

# ---------------------------------------------------------------------------
# Page Header
# ---------------------------------------------------------------------------
st.markdown("""
    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
        <span style="font-size: 2rem;">🔐</span>
        <div>
            <div style="font-weight: 800; font-size: 1.6rem; color: #1E293B;">
                Quantum-Proof Credential Vault
            </div>
            <div style="color: #64748B; font-size: 0.85rem;">
                CRYSTALS-Kyber-768 simulated post-quantum encryption for admin credentials
            </div>
        </div>
    </div>
""", unsafe_allow_html=True)

st.markdown("---")

# ---------------------------------------------------------------------------
# PQC Algorithm Info
# ---------------------------------------------------------------------------
pqc_meta = pqc_vault.get_pqc_metadata()

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("🔒 Algorithm", pqc_meta["algorithm"].split(" (")[0])
with col2:
    st.metric("🔑 Key Size", f"{pqc_meta['key_size']} bits")
with col3:
    st.metric("🛡️ NIST Level", pqc_meta["quantum_resistance_level"].split(" ")[-1])
with col4:
    st.metric("🔬 Security Basis", pqc_meta["security_assumption"])

st.markdown("---")

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------
tab1, tab2, tab3 = st.tabs(["🔐 Credential Vault", "🔑 Key Management", "🧪 Encryption Demo"])

# ===== TAB 1: Credential Vault =====
with tab1:
    st.markdown("#### 🔐 Admin Credential Vault")

    users = mongo_client.find("users")

    if users:
        vault_data = []
        for user in users:
            vault = user.get("pqc_vault", {})
            if not vault:
                continue

            # Check rotation status
            rotation = pqc_vault.check_rotation_status(vault)
            shield_text, shield_color = pqc_vault.get_quantum_shield_badge(rotation["status"])

            vault_data.append({
                "User": user.get("username", ""),
                "Role": user.get("role", ""),
                "Algorithm": vault.get("algorithm", "N/A"),
                "Key Size": f"{vault.get('key_size_bits', 0)} bits",
                "Fingerprint": vault.get("pqc_fingerprint", "")[:12] + "...",
                "Quantum Level": vault.get("quantum_resistance_level", "N/A"),
                "Shield Status": shield_text,
                "Age (Days)": rotation.get("age_days", 0),
                "Needs Rotation": "🔴 Yes" if rotation["needs_rotation"] else "🟢 No",
            })

        df = pd.DataFrame(vault_data)
        st.dataframe(df, use_container_width=True, hide_index=True)

        # Individual credential cards
        st.markdown("---")
        st.markdown("#### 🛡️ Credential Details")

        selected_user = st.selectbox(
            "Select user for detailed view",
            options=[u.get("username") for u in users if u.get("pqc_vault")],
        )

        if selected_user:
            user_data = next((u for u in users if u.get("username") == selected_user), None)
            if user_data:
                vault = user_data.get("pqc_vault", {})
                rotation = pqc_vault.check_rotation_status(vault)
                shield_text, shield_color = pqc_vault.get_quantum_shield_badge(rotation["status"])

                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"""
                        <div style="background: linear-gradient(135deg, #F0F7FF, #F1F5F9);
                                    border: 1px solid #BEE3F8; border-radius: 16px;
                                    padding: 24px; min-height: 300px;
                                    box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
                            <div style="font-weight: 700; color: #0066CC; font-size: 1.1rem;
                                        margin-bottom: 16px;">
                                🔐 Credential — {selected_user}
                            </div>
                            <div style="margin-bottom: 12px;">
                                <span class="quantum-shield-{'active' if rotation['status'] == 'ACTIVE' else 'degraded'}">
                                    {shield_text}
                                </span>
                            </div>
                            <div style="color: #475569; font-size: 0.85rem; line-height: 2;">
                                <strong>Role:</strong> {user_data.get('role', '')}<br>
                                <strong>Algorithm:</strong> {vault.get('algorithm', 'N/A')}<br>
                                <strong>Key Size:</strong> {vault.get('key_size_bits', 0)} bits<br>
                                <strong>Quantum Resistance:</strong> {vault.get('quantum_resistance_level', 'N/A')}<br>
                                <strong>Fingerprint:</strong>
                                <code>{vault.get('pqc_fingerprint', 'N/A')}</code>
                            </div>
                        </div>
                    """, unsafe_allow_html=True)

                with col2:
                    enc_meta = vault.get("encryption_metadata", {})
                    created = vault.get("created_at", "N/A")
                    if isinstance(created, datetime.datetime):
                        created_str = created.strftime("%Y-%m-%d %H:%M")
                    else:
                        created_str = str(created)

                    last_rot = vault.get("last_rotated", "N/A")
                    if isinstance(last_rot, datetime.datetime):
                        rot_str = last_rot.strftime("%Y-%m-%d %H:%M")
                    else:
                        rot_str = str(last_rot)

                    st.markdown(f"""
                        <div style="background: linear-gradient(135deg, #F0F7FF, #F1F5F9);
                                    border: 1px solid #BEE3F8; border-radius: 16px;
                                    padding: 24px; min-height: 300px;
                                    box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
                            <div style="font-weight: 700; color: #0066CC; font-size: 1.1rem;
                                        margin-bottom: 16px;">
                                🔧 Encryption Metadata
                            </div>
                            <div style="color: #475569; font-size: 0.85rem; line-height: 2;">
                                <strong>KEM Algorithm:</strong> {enc_meta.get('kem_algorithm', 'N/A')}<br>
                                <strong>Symmetric:</strong> {enc_meta.get('symmetric_algorithm', 'N/A')}<br>
                                <strong>KDF:</strong> {enc_meta.get('kdf', 'N/A')}<br>
                                <strong>Nonce Size:</strong> {enc_meta.get('nonce_size', 'N/A')}<br>
                                <strong>Created:</strong> {created_str}<br>
                                <strong>Last Rotated:</strong> {rot_str}<br>
                                <strong>Age:</strong> {rotation.get('age_days', 0)} days
                            </div>
                        </div>
                    """, unsafe_allow_html=True)

                # Rotation button
                if rotation["needs_rotation"]:
                    st.warning(f"⚠️ Credential for **{selected_user}** is {rotation['age_days']} days old and requires rotation!")
                    if st.button(f"🔄 Rotate Credential for {selected_user}", key=f"rotate_{selected_user}"):
                        new_vault = pqc_vault.rotate_credential(vault)
                        mongo_client.update_one(
                            "users",
                            {"username": selected_user},
                            {"$set": {"pqc_vault": new_vault, "pqc_key": new_vault["pqc_public_key"]}}
                        )
                        mongo_client.log_audit_event(
                            actor=st.session_state.get("username", "system"),
                            action="CREDENTIAL_ROTATION",
                            target=selected_user,
                            rationale=f"PQC credential rotated. New fingerprint: {new_vault['pqc_fingerprint']}",
                            event_type="security",
                        )
                        st.success(f"✅ Credential rotated for {selected_user}!")
                        st.rerun()

# ===== TAB 2: Key Management =====
with tab2:
    st.markdown("#### 🔑 PQC Key Management")

    st.markdown("""
        <div class="ai-insight-card">
            <div style="font-weight: 700; color: #0066CC; margin-bottom: 8px;">
                ℹ️ About Post-Quantum Cryptography
            </div>
            <div style="color: #334155; font-size: 0.9rem; line-height: 1.7;">
                SentinelIQ uses a simulated CRYSTALS-Kyber-768 key encapsulation mechanism
                (KEM) to protect admin credentials against future quantum computing attacks.
                Kyber is a lattice-based scheme selected by NIST for post-quantum standardization.
                The simulation demonstrates the key lifecycle: generation → encryption →
                rotation → re-encryption.
            </div>
        </div>
    """, unsafe_allow_html=True)

    # Generate new keypair demo
    st.markdown("##### 🔑 Generate New PQC Keypair")
    if st.button("⚡ Generate Kyber-768 Keypair", key="gen_keypair"):
        with st.spinner("🔮 Generating lattice-based keypair..."):
            keypair = pqc_vault.generate_keypair()

        col1, col2 = st.columns(2)
        with col1:
            st.success("✅ Keypair generated!")
            st.code(f"Public Key Hash:  {keypair['public_key'][:32]}...\n"
                    f"Private Key Hash: {keypair['private_key'][:32]}...\n"
                    f"Fingerprint:      {keypair['public_key_fingerprint']}\n"
                    f"Algorithm:        {keypair['algorithm']}\n"
                    f"Key Size:         {keypair['key_size_bits']} bits\n"
                    f"Quantum Level:    {keypair['quantum_resistance_level']}",
                    language="text")
        with col2:
            st.info("🔐 Key Properties")
            st.markdown(f"""
                | Property | Value |
                |----------|-------|
                | Algorithm | CRYSTALS-Kyber-768 |
                | NIST Level | 3 |
                | Security Basis | Module-LWE |
                | Classical Security | ~192-bit |
                | Quantum Security | ~128-bit |
            """)

    # Bulk rotation
    st.markdown("---")
    st.markdown("##### 🔄 Bulk Credential Rotation")
    st.info("Rotate all credentials that are older than 30 days.")

    if st.button("🔄 Rotate All Expired Credentials", key="bulk_rotate"):
        users = mongo_client.find("users")
        rotated = 0
        for user in users:
            vault = user.get("pqc_vault", {})
            if vault:
                rotation = pqc_vault.check_rotation_status(vault)
                if rotation["needs_rotation"]:
                    new_vault = pqc_vault.rotate_credential(vault)
                    mongo_client.update_one(
                        "users",
                        {"username": user["username"]},
                        {"$set": {"pqc_vault": new_vault, "pqc_key": new_vault["pqc_public_key"]}}
                    )
                    rotated += 1

        if rotated > 0:
            st.success(f"✅ Rotated {rotated} credential(s)!")
        else:
            st.info("✅ All credentials are up to date — no rotation needed.")

# ===== TAB 3: Encryption Demo =====
with tab3:
    st.markdown("#### 🧪 PQC Encryption / Decryption Demo")

    st.markdown("""
        <div class="ai-insight-card">
            <div style="font-weight: 700; color: #0066CC; margin-bottom: 8px;">
                🧪 How It Works
            </div>
            <div style="color: #334155; font-size: 0.9rem; line-height: 1.7;">
                1. A Kyber-768 keypair is generated (lattice-based KEM)<br>
                2. The public key encapsulates a shared secret<br>
                3. The shared secret derives an AES-256-GCM symmetric key via HKDF<br>
                4. The plaintext is encrypted with AES-256-GCM<br>
                5. Only the matching private key can decapsulate and decrypt
            </div>
        </div>
    """, unsafe_allow_html=True)

    plaintext = st.text_input("Enter text to encrypt", value="SuperSecretBankingCredential_2026!")

    if st.button("🔐 Encrypt with PQC", key="encrypt_demo"):
        with st.spinner("🔮 Encrypting with simulated Kyber-768..."):
            keypair = pqc_vault.generate_keypair()
            encrypted = pqc_vault.encrypt_credential(plaintext, keypair["public_key"])

        st.success("✅ Encrypted!")

        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**📤 Ciphertext:**")
            st.code(encrypted["ciphertext"][:80] + "...", language="text")
            st.markdown("**🔑 KEM Ciphertext:**")
            st.code(encrypted["kem_ciphertext"], language="text")

        with col2:
            st.markdown("**📋 Encryption Metadata:**")
            meta = encrypted["encryption_metadata"]
            st.json(meta)

        # Decrypt
        st.markdown("---")
        st.markdown("**🔓 Decrypting with private key...**")
        decrypted = pqc_vault.decrypt_credential(encrypted, keypair["private_key"])
        if decrypted:
            st.success(f"✅ Decrypted: `{decrypted}`")
        else:
            st.error("❌ Decryption failed (key mismatch)")

        # Show that wrong key fails
        st.markdown("**🚫 Attempting decryption with WRONG key...**")
        wrong_keypair = pqc_vault.generate_keypair()
        bad_decrypt = pqc_vault.decrypt_credential(encrypted, wrong_keypair["private_key"])
        if bad_decrypt is None:
            st.error("❌ Decryption failed with wrong key — PQC protection verified!")
        else:
            st.warning("⚠️ Unexpected: decryption succeeded with wrong key")
