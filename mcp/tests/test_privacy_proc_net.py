"""/proc/net tables print addresses as little-endian hex: the model must still only see placeholders."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.privacy import DEFAULT_CATEGORIES  # noqa: E402
from src.privacy.gateway import CommandGateway, decode_proc_net_addresses  # noqa: E402
from src.privacy.vault import PrivacyVault  # noqa: E402

TCP = ("  sl  local_address rem_address   st tx_queue rx_queue\n"
       "   0: 030014AC:A472 020014AC:1395 01 00000000:00000000\n"
       "   1: 0000000000000000FFFF00000200140A:1395 00000000000000000000000000000000:0000 0A\n")


def test_hex_addresses_of_proc_net_tcp_are_masked():
    out = CommandGateway().sanitize_output(TCP, PrivacyVault(session_id="t", ttl_seconds=60,
                                                             enabled_categories=DEFAULT_CATEGORIES))
    for leak in ("020014AC", "030014AC", "0200140A", "172.20.0", "10.20.0.2"):
        assert leak not in out
    assert ":5013" in out and "IP_PRIVATE_" in out


def test_hex_outside_a_proc_net_table_is_left_alone():
    text = "commit 020014AC:1395 deadbeef"
    assert decode_proc_net_addresses(text) == text
