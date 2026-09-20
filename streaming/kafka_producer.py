"""
Kafka Producer — replaces Cell 23's Event Hubs producer.

Usage: after generating `security_events` in the notebook, either
call publish_events(security_events) directly from a notebook cell,
or export security_events to security_events.jsonl and run this
script standalone to replay them.
"""

import json
import time

from kafka import KafkaProducer

KAFKA_BOOTSTRAP_SERVERS = "localhost:9092"
TOPIC_NAME = "network-events"


def get_producer():
    return KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )


def publish_events(events, delay_seconds=1):
    producer = get_producer()

    print(f"Connected to Kafka at {KAFKA_BOOTSTRAP_SERVERS}")
    print(f"Publishing to topic: {TOPIC_NAME}")
    print("-" * 70)

    for event_number, event in enumerate(events, start=1):
        producer.send(TOPIC_NAME, value=event)
        producer.flush()

        print(
            f"Sent event {event_number}/{len(events)} | "
            f"{event.get('attack_type', 'UNKNOWN'):12} | "
            f"{event.get('severity', 'n/a')}"
        )

        time.sleep(delay_seconds)

    print("\nAll security events sent successfully.")
    producer.close()


if __name__ == "__main__":
    # Standalone mode: replay from the JSONL file the notebook exports
    events = []
    with open("security_events.jsonl", "r") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))

    publish_events(events)
