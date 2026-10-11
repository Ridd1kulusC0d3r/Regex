# STIX 2.1 e catálogo OSINT

**Interpretação crítica:** este toolkit transforma *candidatos de texto* em representações estruturadas. Não valida ameaça, reputação, propriedade de infraestrutura ou ocorrência de ataque.

## Pipeline local

```bash
python3 osint_regex.py examples/sample_report.txt > candidates.jsonl
python3 pattern_catalog.py --check
python3 pattern_catalog.py --group vulnerabilidades --json
python3 casebook.py candidates.jsonl --format markdown > casebook.md
python3 stix_export.py candidates.jsonl --provenance-out evidence.jsonl > bundle.stix.json
```

## Semântica STIX

- A saída é um `bundle` de **SCOs STIX 2.1**: `ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `email-addr`, `file` (hashes MD5, SHA-1, SHA-256 e SHA-512).
- Não cria objetos `Indicator`, `Observed Data`, `Sighting` ou `Relationship`. Uma ocorrência textual não equivale a observação de rede, ameaça ou associação entre objetos.
- Por padrão, emails e URLs com query ou fragmento são excluídos, para minimizar dados pessoais/tokens. `--include-sensitive` só deve ser usado com autorização e retenção adequada.
- O sidecar `evidence.jsonl` mapeia cada objeto ao arquivo, linha e coluna, mas **não é parte da especificação STIX**. Guarde-o separadamente e proteja caminhos internos.
- IDs dos SCOs e do bundle usam UUID v4 novos a cada execução. Deduplicação por tipo/valor existe apenas dentro da mesma execução; não equivale a identidade canônica inter-organizações.
- A ferramenta revalida candidatos normalizados de entrada JSONL e limita comprimento de linha e quantidade de registros. Um sidecar existente não é sobrescrito.
- Identificadores de vulnerabilidades (CVE/GHSA/CWE/CAPEC) não são convertidos em SCOs, pois isso precisaria de modelagem diferente e mais contexto.

## Limites do catálogo

O comando `pattern_catalog.py --list` exibe o regex de cada tipo, grupo e um exemplo testável. `--search` e `--group` filtram. `--json` oferece metadados estruturados. `--check` verifica se há cobertura integral do extrator e valida os exemplos. Regex sem `_normalize` não equivale a validação semântica.

## Fontes normativas

- [OASIS STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html)
- [STIX 2.1 errata e Bundle](https://docs.oasis-open.org/cti/stix/v2.1/csd01/stix-v2.1-errata01-csd01-complete.html)
- [Identificadores GHSA](https://docs.github.com/en/code-security/concepts/vulnerability-reporting-and-management/github-advisory-database)
- [MITRE CAPEC](https://capec.mitre.org/)
- [MITRE CWE](https://cwe.mitre.org/)

A estrutura é testada com unittest. **Não foi executada uma validação independente do bundle usando um validador STIX externo**.
