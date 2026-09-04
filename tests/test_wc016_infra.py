from pathlib import Path

ROOT = Path(__file__).parents[1]
BICEP = ROOT / "infra" / "wc016-event-reassessment" / "main.bicep"


def test_wc016_service_bus_is_private_keyless_and_duplicate_safe() -> None:
    source = BICEP.read_text(encoding="utf-8")

    assert "sku:" in source and "Premium" in source
    assert "publicNetworkAccess: 'Disabled'" in source
    assert "disableLocalAuth: true" in source
    assert "privateEndpoints@2024-05-01" in source
    assert "requiresDuplicateDetection: true" in source
    assert "deadLetteringOnMessageExpiration: true" in source
    assert "requiresSession: true" in source
    assert "Azure Service Bus Data Sender" not in source
    assert "listKeys(" not in source


def test_wc016_transport_has_separate_event_reassessment_and_notification_queues() -> None:
    source = BICEP.read_text(encoding="utf-8")

    assert "'raw-monitor-events'" in source
    assert "'incident-reassessment-requests'" in source
    assert "'incident-notification-outbox'" in source
    assert "autoRemediation: 'disabled'" in source
