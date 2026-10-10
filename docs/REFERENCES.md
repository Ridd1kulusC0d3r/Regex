# Referências técnicas verificáveis

Estas fontes orientaram a arquitetura, as categorias e os alertas de segurança. **Nenhum código externo foi copiado.** Confira sempre licenças e versões antes de incorporar dependências.

| Referência | Aplicação no toolkit |
|---|---|
| [IOC Finder (fhightower)](https://github.com/fhightower/ioc-finder) | Regex como filtro de candidatos e gramáticas/validação como etapa separada |
| [iocextract](https://pypi.org/project/iocextract/) | Indicadores neutralizados (defanged) e normalização textual |
| [CyberChef (GCHQ)](https://github.com/gchq/CyberChef) | Taxonomia de operações de extração e regex para artefatos |
| [MITRE ATT&CK IDs](https://mitre-attack.github.io/attack-data-model/schemas/attack-ids/) | Formatos de técnicas, subtécnicas e táticas |
| [Python: ipaddress](https://docs.python.org/3/library/ipaddress.html) | Validação efetiva de IPv4/IPv6/CIDR |
| [Python: re](https://docs.python.org/3/library/re.html) | Sintaxe e comportamento do mecanismo regex utilizado |
| [OWASP: ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS) | Risco de expressões com retrocesso catastrófico |
| [GitHub Security Lab: ReDoS](https://github.blog/security/how-to-fix-a-redos/) | Estratégias de correção e teste de regex custosas |
| [CodeQL: py/redos](https://codeql.github.com/codeql-query-help/python/py-redos/) | Avaliação estática de desempenho e disponibilidade |

## O que avaliar antes de ampliar

- **Qualidade:** evidências de precisão (falsos positivos e falsos negativos), corpus de teste e casos de borda.
- **Segurança:** desempenho no pior caso, limites de entrada, URLs com dados pessoais.
- **Interoperabilidade:** exportação para STIX, MISP e pipelines SIEM/OSINT somente quando houver caso de uso real.
- **Rastreabilidade:** fonte, linha, posição, texto original e transformações aplicadas.
- **Licenças:** estudo de projetos não equivale a permissão para copiar expressões, dados ou implementação indiscriminadamente.
