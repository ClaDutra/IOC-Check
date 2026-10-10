import os

from dotenv import load_dotenv

load_dotenv()


class Config:
    # Quando vazio, create_app() aponta para instance/ioc_check.db
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Cache de consultas: tempo de validade de um resultado armazenado
    CACHE_TTL_HOURS = int(os.getenv("CACHE_TTL_HOURS", "24"))
    # Resultados com falha em algum provedor expiram mais cedo
    CACHE_ERROR_TTL_MINUTES = int(os.getenv("CACHE_ERROR_TTL_MINUTES", "10"))

    # Integrações externas (opcionais). Valores salvos na tela de
    # Configurações têm prioridade sobre estes.
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    THREATFOX_API_KEY = os.getenv("THREATFOX_API_KEY", "").strip()
    HYBRID_ANALYSIS_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY", "").strip()
    URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "").strip()
    PROVIDER_TIMEOUT = int(os.getenv("PROVIDER_TIMEOUT", "8"))

    # Validade padrão de um IOC cadastrado sem prazo informado (0 = nunca expira)
    IOC_DEFAULT_EXPIRATION_DAYS = int(os.getenv("IOC_DEFAULT_EXPIRATION_DAYS", "90"))

    MAX_INDICATORS_PER_CHECK = 50


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    VIRUSTOTAL_API_KEY = ""
    ABUSEIPDB_API_KEY = ""
    THREATFOX_API_KEY = ""
    HYBRID_ANALYSIS_API_KEY = ""
    URLSCAN_API_KEY = ""
    # Nos testes nenhuma chamada de rede é feita, a menos que o teste simule a API
    URLSCAN_ENABLED_BY_DEFAULT = False
