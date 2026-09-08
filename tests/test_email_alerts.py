import json
from unittest.mock import patch

import pandas as pd

from risk_scoring import send_admin_risk_alerts, send_high_risk_alerts


def test_send_high_risk_alerts_uses_registered_email(tmp_path):
    users_file = tmp_path / "users.json"
    users_file.write_text(
        json.dumps([
            {"username": "alice", "email": "alice@example.com"},
            {"username": "bob", "email": "bob@example.com"},
        ]),
        encoding="utf-8",
    )

    scored_df = pd.DataFrame([
        {"Username": "alice", "Risk_Score": 88, "Detection_Reason": "Suspicious activity detected"},
        {"Username": "alice", "Risk_Score": 72, "Detection_Reason": "Repeated anomalous requests"},
        {"Username": "bob", "Risk_Score": 30, "Detection_Reason": "Low risk"},
    ])

    with patch("risk_scoring.send_email", return_value=True) as mock_send_email:
        sent = send_high_risk_alerts(scored_df, users_file=users_file)

    assert len(sent) == 1
    assert sent[0]["username"] == "alice"
    assert sent[0]["email"] == "alice@example.com"
    assert mock_send_email.call_count == 1
    assert mock_send_email.call_args[0][0] == "alice@example.com"


def test_send_admin_risk_alert_includes_person_category_and_score():
    scored_df = pd.DataFrame([
        {
            "Username": "alice",
            "Risk_Score": 88,
            "Risk_Category": "Critical Risk",
            "Detection_Reason": "Repeated anomalous requests",
        },
        {
            "Username": "bob",
            "Risk_Score": 30,
            "Risk_Category": "Low Risk",
            "Detection_Reason": "No strong suspicious signals",
        },
    ])

    with patch("risk_scoring.send_email", return_value=True) as mock_send_email:
        sent = send_admin_risk_alerts(scored_df, admin_email="admin@example.com")

    assert sent is True
    recipient, subject, message = mock_send_email.call_args[0][:3]
    assert recipient == "admin@example.com"
    assert "alice" in message
    assert "Critical Risk" in message
    assert "88/100" in message
    assert "bob" not in message
    assert "Risk Alert" in subject
