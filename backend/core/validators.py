from django.core.validators import RegexValidator

sha256_validator = RegexValidator(r"^[0-9a-f]{64}$", "Must be a lowercase 64-character hex SHA-256.")
