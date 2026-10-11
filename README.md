# Regex OSINT Toolkit

> **Versão 2: extração, DNS e proveniência**. Biblioteca de padrões **Regex + validação semântica** para OSINT, análise de artefatos e Cyber Threat Intelligence (CTI). **Offline-first, sem APIs, sem rastreamento e sem dependências externas.**

[![Python tests](https://github.com/Ridd1kulusC0d3r/Regex/actions/workflows/tests.yml/badge.svg)](https://github.com/Ridd1kulusC0d3r/Regex/actions/workflows/tests.yml)
![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776ab)
![Offline](https://img.shields.io/badge/processing-offline-166534)

## O que é

Um laboratório prático de expressões regulares para **identificar candidatos a indicadores** em relatórios, logs, notas de investigação e arquivos locais. A extração acontece sem conexão de rede. O parser DNS lê somente arquivos locais; não resolve domínios. Padrões são deliberadamente legíveis, e a validação com bibliotecas Python evita alguns falsos positivos clássicos (como IPv4 fora do intervalo 0–255).

**O que não é:** scanner de alvos, mecanismo de atribuição, base de reputação, confirmação de IOC malicioso, validador completo de RFC 5322 ou substituto de bibliotecas especializadas. Encontrar uma string não prova comprometimento nem identidade.

## Comece em 30 segundos

```bash
git clone https://github.com/Ridd1kulusC0d3r/Regex.git
cd Regex
python3 osint_regex.py --list-types
python3 osint_regex.py examples/sample_report.txt
python3 osint_regex.py examples/sample_report.txt --types ipv4,cve,domain --format csv
python3 -m unittest discover -s tests -v
```

Pipe de texto (também funciona em macOS e Linux):

```bash
cat examples/sample_report.txt | python3 osint_regex.py --unique
python3 osint_regex.py casos/*.txt --types url,email,sha256 --max-matches 1000 > indicadores.jsonl
```

Os resultados são emitidos como **JSONL** (um JSON por linha) ou **CSV** com campos `type`, `value`, `raw`, `source`, `line` e `column`. A linha e a coluna referem-se ao texto original, antes de qualquer normalização.

## DNS Intelligence e grafo de relacionamentos

O módulo `dns_osint.py` interpreta **arquivos de zona com um registro por linha e owner FQDN absoluto**. Não realiza consultas DNS e não interpreta zonas completas com `$ORIGIN`, `@` ou records multiline.

```bash
python3 dns_osint.py parse examples/sample_dns.zone > dns.jsonl
python3 dns_osint.py graph dns.jsonl > graph.json
```

Tipos: A, AAAA, NS, MX, CNAME, PTR e TXT (apenas SPF/DMARC por padrão). Registros TXT de verificação podem conter tokens, por isso são ignorados, salvo com `--include-txt`. O grafo liga nomes a alvos de registros tipados, anota arquivo/linha e **não infere vínculos por simples coocorrência**. Veja [guia de infraestrutura](docs/DNS-INTELLIGENCE.md).

## Manifesto de evidência

```bash
python3 evidence_manifest.py examples/sample_dns.zone
```

Gera SHA-256, tamanho e data de última modificação de arquivo (UTC). Não extrai EXIF/GPS e não prova autoria ou data de criação; symlinks e arquivos maiores que 100 MiB são rejeitados por padrão.

## Novos módulos de triagem e interoperabilidade (v3)

**Catálogo vivo:** `python3 pattern_catalog.py --list` mostra todas as expressões com propósito, nível de cautela, exemplos e regex. `python3 pattern_catalog.py --search vulnerabilidade --json` produz metadados legíveis por máquina.

**Exportação STIX 2.1:** `stix_export.py` transforma indicadores **candidatos já extraídos** em SCOs (objetos cyber-observable) sem supor comportamento malicioso ou observação de rede. O bundle não cria relações nem objetos Indicator/Observed Data. E-mails e URLs com query/fragment são filtrados por padrão; aceite-os explicitamente apenas em ambiente autorizado. Consulte [guia STIX](docs/STIX-EXPORT.md).

**Relatório investigativo:** `casebook.py` resume ocorrências por tipo, valor e fonte, com contagens auditáveis, sem inventar vínculos entre entidades.

```bash
python3 osint_regex.py examples/sample_report.txt > /tmp/candidates.jsonl
python3 pattern_catalog.py --list
python3 casebook.py /tmp/candidates.jsonl --format markdown > /tmp/casebook.md
python3 stix_export.py /tmp/candidates.jsonl --provenance-out /tmp/evidence.jsonl > /tmp/bundle.stix.json
```

## Catálogo

| Grupo | Tipos implementados |
|---|---|
| Infraestrutura | `ipv4`, `ipv6`, `ipv4_cidr`, `domain`, `url`, `email`, `asn`, `mac` |
| Referências documentais | `doi` (identificadores bibliográficos, sem resolução) |
| Artefatos | `md5`, `sha1`, `sha256`, `sha512` |
| Threat intelligence | `cve`, `cwe`, `capec`, `ghsa`, `attack_technique`, `attack_tactic`, `attack_group`, `attack_software`, `attack_mitigation`, `stix_id` |

Há suporte a indicadores parcialmente neutralizados, como `hxxps[:]//portal[.]example` e `203[.]0[.]113[.]7`. A normalização é **textual**, jamais navega no endereço extraído.

Consulte [catálogo técnico de padrões](docs/PATTERNS.md) e [fontes de pesquisa](docs/REFERENCES.md).

## Estrutura

```text
Regex/
├── pattern_catalog.py            # Catálogo de regex pesquisável
├── casebook.py                   # Resumo agrupado e proveniência
├── stix_export.py                # Bundle STIX 2.1 de candidatos validados
├── dns_osint.py                 # Parser DNS e grafo de evidências
├── evidence_manifest.py        # SHA-256 e metadados locais
├── osint_regex.py              # Extrator CLI e API Python
├── tests/test_osint_regex.py   # Testes de regressão
├── examples/sample_report.txt  # Amostra sintética
├── docs/PATTERNS.md            # Tipos, limites e exemplos
├── docs/REFERENCES.md          # Fontes verificáveis
└── .github/workflows/tests.yml # CI em Python
```

## Uso como biblioteca

```python
from osint_regex import extract

texto = "Relatório: CVE-2024-12345 e hxxps://portal[.]example/arquivo"
for indicador in extract(texto, source="relatorio-interno"):
    print(indicador["type"], indicador["value"], indicador["line"])
```

## Interpretação responsável

- **Regex não confirma malícia, titularidade ou existência.** É filtro para triagem com verificação posterior.
- **Privacidade:** e-mails, caminhos e URLs podem conter dados pessoais ou tokens. Revise o output antes de compartilhar; URLs com credenciais embutidas são rejeitadas.
- **Desempenho:** `--max-line-length` (padrão 100.000 caracteres) e `--max-matches` (padrão 10.000) limitam volume processado. Linhas muito longas são ignoradas com aviso.
- **Precisão:** suporte a domínios ASCII e protocolos HTTP(S); URLs complexas, IDN, IPv6 dentro de URLs e e-mails RFC completos requerem parsers especializados. Não há consulta ao Public Suffix List.
- **Uso autorizado:** processe apenas dados que você pode analisar legitimamente e respeite políticas de retenção e proteção de dados.

## Roadmap

- [x] Extração local de indicadores com origem/posição e exportação JSONL/CSV.
- [x] Tratamento básico de indicadores neutralizados e testes automatizados.
- [x] Parser DNS offline com grafo de relações tipadas e proveniência.
- [x] Manifesto de evidências SHA-256, tamanho e mtime.
- [x] CWE, CAPEC, GHSA, grupos/software/mitigações ATT&CK.
- [x] Catálogo de padrões e matriz de validação automatizada.
- [x] Exportação STIX 2.1 (SCOs sem afirmação de malícia) e casebook local.
- [ ] Domínios IDN, Public Suffix List e parsers especializados opcionais.
- [ ] Testes por fuzzing e benchmarks ReDoS reproduzíveis.
- [ ] Integração opcional com STIX 2.1 e enriquecimento somente com consentimento explícito.
- [ ] Catálogo comunitário de padrões com testes de positivos/negativos.

Contribuições: [CONTRIBUTING.md](CONTRIBUTING.md). A implementação é original; referências servem como material de estudo e comparação, não como código copiado.
