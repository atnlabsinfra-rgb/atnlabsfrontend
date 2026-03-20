# services/text_security_service.py
"""
Rule-based scam pattern detection using regex.
Returns a list of triggered flag names.
Results are passed to the AI service as context.
"""
import re
from typing import List

RULES: list[tuple[str, list[str]]] = [
    ("urgent_language", [
        r"\burgent\b", r"\bimmediately\b", r"\bact now\b", r"\bexpires?\b",
        r"\blast chance\b", r"\bwithin \d+ hours?\b", r"\btoday only\b",
        r"\bdeadline\b", r"\bdo not delay\b", r"\btime.?sensitive\b",
    ]),
    ("otp_request", [
        r"\botp\b", r"\bone.?time.?pass(word|code)?\b", r"\bverification code\b",
        r"\bdo not share.*code\b", r"\bnever share.*otp\b",
        r"\benter.*code\b", r"\bconfirm.*code\b",
    ]),
    ("suspicious_link", [
        r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        r"https?://[^\s]*\.(xyz|top|tk|ml|ga|cf|gq|pw)",
        r"bit\.ly|tinyurl|t\.co|goo\.gl|shorturl",
        r"https?://[^\s]*(login|verify|secure|update|account|confirm)[^\s]*",
    ]),
    ("impersonation", [
        r"\b(sbi|hdfc|icici|axis|kotak|rbi|npci|uidai|aadhar|aadhaar)\b",
        r"\b(income tax|it department|government of india|goi)\b",
        r"\b(amazon|flipkart|paytm|phonepe|google pay|gpay)\b",
        r"\b(police|cbi|enforcement directorate|\bed\b|cyber cell)\b",
        r"\byour (bank|account|kyc|card) (has been|will be) (blocked|suspended|deactivated)\b",
    ]),
    ("money_request", [
        r"\bsend money\b", r"\btransfer.{0,20}(rs\.?|inr|₹|\$|usd)",
        r"\bpay.{0,10}(now|immediately|today)\b",
        r"\bcash\s*prize\b", r"\byou (have won|are selected|are eligible)\b",
        r"\bclaim your (prize|reward|gift|cashback)\b",
        r"\bwire transfer\b", r"\bgift card\b",
    ]),
]


def check_text(text: str) -> List[str]:
    """
    Returns a list of triggered rule names.
    Each rule is counted at most once even if multiple patterns match.
    Empty list means no suspicious patterns detected.
    """
    text_lower = text.lower()
    triggered = []
    for rule_name, patterns in RULES:
        for pattern in patterns:
            if re.search(pattern, text_lower):
                triggered.append(rule_name)
                break
    return triggered