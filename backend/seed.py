"""Opcional: carrega IOCs de exemplo para demonstrar o sistema.

O IOC Check começa com a base vazia para você montar a sua. Use este script só
se quiser dados de demonstração (e apague-os depois com "Limpar base").

Os IPs usam faixas reservadas para documentação (RFC 5737), os domínios usam o
TLD .example (RFC 2606) e os hashes são do arquivo de teste EICAR — nenhum deles
é uma ameaça real.

Uso:  python seed.py
"""

from app import create_app
from app.extensions import db
from app.ioc_utils import normalize
from app.models import Ioc

SAMPLE_IOCS = [
    ("198.51.100.23", "critical", "Servidor de comando e controle (C2) de botnet", "botnet,c2", "Relatório interno"),
    ("203.0.113.50", "high", "Origem de varreduras e força bruta em SSH", "brute-force,ssh", "Logs do firewall"),
    ("192.0.2.77", "medium", "Proxy aberto usado em tentativas de fraude", "proxy,fraude", "Relatório interno"),
    ("phishing-login.example", "critical", "Página falsa imitando login bancário", "phishing,banco", "Denúncia de usuário"),
    ("malware-cdn.example", "high", "Distribuição de instaladores com trojan", "malware,trojan", "Análise de incidente"),
    ("suporte-falso.example", "medium", "Golpe de falso suporte técnico", "golpe,engenharia-social", "Denúncia de usuário"),
    ("cobranca@fatura-pendente.example", "high", "Remetente de e-mails de phishing com boleto falso", "phishing,boleto", "Caixa de e-mail corporativa"),
    ("44d88612fea8a8f36de82e1278abb02f", "high", "Arquivo de teste EICAR (MD5)", "eicar,teste", "EICAR"),
    ("3395856ce81f2b7382dee72602f798b642f14140", "high", "Arquivo de teste EICAR (SHA1)", "eicar,teste", "EICAR"),
    ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "high", "Arquivo de teste EICAR (SHA256)", "eicar,teste", "EICAR"),
    ("http://download-atualizacao.example/setup.exe", "critical", "Falso instalador de atualização", "malware,dropper", "Análise de incidente"),
    ("2001:db8::bad:1", "low", "Endereço IPv6 observado em varreduras", "scan", "Logs do firewall"),
]


def run():
    app = create_app()
    with app.app_context():
        added = 0
        for raw, severity, description, tags, source in SAMPLE_IOCS:
            value, ioc_type = normalize(raw)
            if Ioc.query.filter_by(value=value).first():
                continue
            db.session.add(Ioc(
                value=value, ioc_type=ioc_type, severity=severity, description=description,
                tags=tags, source=source,
            ))
            added += 1

        db.session.commit()
        print(f"{added} IOC(s) de exemplo inserido(s).")


if __name__ == "__main__":
    run()
