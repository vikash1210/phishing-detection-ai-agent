
import os

import requests
import streamlit as st


API_URL = os.getenv(
    "PHISHING_API_URL",
    "http://127.0.0.1:8000",
).rstrip("/")


st.set_page_config(
    page_title="Phishing Detection AI Agent",
    page_icon="🛡️",
    layout="centered",
)

st.title("Phishing Detection AI Agent")
st.write(
    "Analyze a URL using a pretrained ML classifier, "
    "Google Safe Browsing threat intelligence, and RAG-based "
    "security guidance."
)

url = st.text_input(
    "Enter a URL",
    placeholder="https://example.com",
)

if st.button("Check URL", type="primary"):
    if not url.strip():
        st.warning("Please enter a URL.")

    else:
        try:
            with st.spinner(
                "Analyzing URL, checking threat intelligence, "
                "and retrieving security guidance..."
            ):
                response = requests.post(
                    f"{API_URL}/predict",
                    json={"url": url.strip()},
                    timeout=60,
                )

            if response.status_code == 422:
                try:
                    error_data = response.json()
                    detail = error_data.get(
                        "detail",
                        "Enter a valid HTTP or HTTPS URL.",
                    )
                except ValueError:
                    detail = "Enter a valid HTTP or HTTPS URL."

                st.error(f"Invalid URL: {detail}")

            else:
                response.raise_for_status()
                result = response.json()

                # 1. ML classification
                st.subheader("Classification Result")

                prediction = result.get("prediction", "unknown")
                score = result.get("phishing_score")

                if prediction == "phishing":
                    st.error(
                        "Potential phishing URL detected by the ML model."
                    )
                elif prediction == "legitimate":
                    st.success(
                        "The ML model classified this URL as legitimate."
                    )
                else:
                    st.warning(
                        f"The ML model returned an unexpected label: "
                        f"{prediction}"
                    )

                if score is not None:
                    st.metric(
                        "Model phishing score",
                        f"{score * 100:.2f}%",
                    )

                st.caption(
                    "This score is a model output, not necessarily a "
                    "calibrated probability. It does not guarantee that "
                    "the URL is safe or malicious."
                )

                # 2. Google Safe Browsing
                st.divider()
                st.subheader("Google Safe Browsing Threat Intelligence")

                threat_info = result.get("threat_intelligence") or {}
                threat_status = threat_info.get("status", "unavailable")

                if threat_status == "threat_found":
                    st.error(
                        "THREAT MATCH: Google Safe Browsing reported "
                        "a threat for this URL."
                    )

                    matches = threat_info.get("matches", [])

                    if matches:
                        st.markdown("**Threat details**")

                        for index, match in enumerate(matches, start=1):
                            threat_type = match.get(
                                "threat_type",
                                "Unknown threat type",
                            )
                            platform_type = match.get(
                                "platform_type",
                                "Unknown platform",
                            )
                            entry_type = match.get(
                                "threat_entry_type",
                                "Unknown entry type",
                            )

                            st.write(
                                f"{index}. Threat type: {threat_type}"
                            )
                            st.caption(
                                f"Platform: {platform_type} | "
                                f"Entry type: {entry_type}"
                            )

                    st.warning(
                        "Avoid visiting this URL. An external threat "
                        "match is a strong warning, even if the ML "
                        "classifier labels it legitimate."
                    )

                elif threat_status == "no_match":
                    st.info(
                        "No matching threat was returned by Google "
                        "Safe Browsing."
                    )
                    st.caption(
                        "No match does not mean the URL is safe. "
                        "New or unlisted threats may not be detected."
                    )

                elif threat_status == "unavailable":
                    st.warning(
                        "Google Safe Browsing is unavailable. "
                        "The URL's threat status could not be verified."
                    )

                elif threat_status == "not_configured":
                    st.warning(
                        "Google Safe Browsing API key is not configured."
                    )

                else:
                    st.warning(
                        f"Threat intelligence status: {threat_status}"
                    )

                message = threat_info.get("message")
                if message:
                    st.caption(message)

                # 3. Final risk assessment
                st.divider()
                st.subheader("Final Risk Assessment")

                risk = result.get("risk_assessment") or {}
                risk_level = risk.get("risk_level", "UNAVAILABLE")
                reasons = risk.get("reasons", [])
                verification_status = risk.get(
                    "verification_status",
                    "unknown",
                )

                if risk_level == "HIGH RISK":
                    st.error("HIGH RISK")
                    st.write(
                        "An external threat-intelligence match was reported. "
                        "Treat this URL as dangerous."
                    )

                elif risk_level == "SUSPICIOUS":
                    st.warning("SUSPICIOUS")
                    st.write(
                        "The ML classifier detected phishing indicators. "
                        "Use caution and do not enter sensitive information."
                    )

                elif risk_level == "UNVERIFIED":
                    st.info("UNVERIFIED")
                    st.write(
                        "The available signals do not establish whether "
                        "this URL is safe. Do not treat this result as "
                        "a safety guarantee."
                    )

                else:
                    st.warning(
                        f"Risk assessment unavailable: {risk_level}"
                    )
                    st.write(
                        "The API did not return a recognized risk level. "
                        "Check the API response and server logs."
                    )

                st.markdown("**Assessment reasons**")

                if reasons:
                    for reason in reasons:
                        st.markdown(f"- {reason}")
                else:
                    st.caption("No assessment reasons were provided.")

                st.markdown("**Verification status**")
                st.code(str(verification_status), language=None)

                # 4. RAG evidence
                st.divider()
                st.subheader("Retrieved Security Evidence")

                evidence = result.get("evidence", [])

                if evidence:
                    for index, item in enumerate(evidence, start=1):
                        source = item.get("source", "Unknown source")

                        with st.expander(
                            f"Evidence {index} - {source}",
                            expanded=(index == 1),
                        ):
                            st.write(
                                item.get("text", "No text available.")
                            )

                            similarity = item.get("similarity")
                            similarity_text = (
                                f"{similarity:.4f}"
                                if similarity is not None
                                else "Unknown"
                            )

                            st.caption(
                                f"Source: {source} | "
                                f"Chunk: {item.get('chunk_id', 'Unknown')} | "
                                f"Similarity: {similarity_text}"
                            )

                else:
                    st.info(
                        "No relevant passages were retrieved from "
                        "the knowledge base."
                    )

                st.warning(
                    result.get(
                        "evidence_note",
                        "Retrieved guidance does not independently verify "
                        "whether this specific URL is malicious or legitimate.",
                    )
                )

        except requests.Timeout:
            st.error(
                "The request timed out. The API, classifier, or "
                "threat-intelligence lookup may be taking too long. "
                "Please try again."
            )

        except requests.RequestException:
            st.error(
                "Could not connect to the API or receive a valid response. "
                "Check that the FastAPI server is running."
            )

        except (KeyError, TypeError, ValueError):
            st.error(
                "The API returned an unexpected response. "
                "Check the FastAPI logs."
            )
