import hashlib


def finding_fingerprint(category: str, url: str, method: str = "GET", parameter: str | None = None) -> str:
    """
    إنشاء بصمة فريدة (Fingerprint) للثغرة لمنع التكرار.
    تعتمد البصمة على نوع الثغرة، الرابط، الـ HTTP Method، والـ Parameter المصاب.
    """
    # تجميع البيانات الأساسية اللي بتميز الثغرة
    raw_string = f"{category.lower().strip()}:{url.strip()}:{method.upper()}:{parameter or ''}"

    # تحويلها لـ SHA-256 Hash
    return hashlib.sha256(raw_string.encode('utf-8')).hexdigest()
