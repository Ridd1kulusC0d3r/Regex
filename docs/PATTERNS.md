# Catálogo técnico de padrões

O mecanismo separa **regex de descoberta** de **validação semântica**. Consulte as expressões completas em [osint_regex.py](../osint_regex.py), que é a fonte da verdade: esta página documenta contratos, não padrões desconectados do código.

| Tipo | Entrada de exemplo | Resultado normalizado | Validação / ressalvas |
|---|---|---|---|
| `url` | `hxxps[:]//portal[.]example/a` | `https://portal.example/a` | Somente HTTP(S), host validável, sem usuário/senha |
| `domain` | `sub[.]example.org` | `sub.example.org` | Labels ASCII, não consulta existência/TLD |
| `email` | `user@demo[.]example` | `user@demo.example` | Sintaxe comum; não cobre todo RFC 5322 |
| `ipv4` | `203[.]0[.]113[.]9` | `203.0.113.9` | Usa `ipaddress`; rejeita 999.1.2.3 |
| `ipv4_cidr` | `198.51.100.7/24` | `198.51.100.7/24` | `ip_interface` preserva bits do host |
| `ipv6` | `2001:db8::1` | `2001:db8::1` | Validação com `ipaddress` |
| `asn` | `AS64500` | `AS64500` | Faixa numérica 32-bit; não valida delegação |
| `mac` | `00:11:22:AA:bb:cc` | `00:11:22:aa:bb:cc` | Formatos hexadecimais comuns |
| `sha512` | 128 hexadecimais | minúsculas | Só formato; sem confirmação de hash |
| `stix_id` | `indicator--e2e1a340-4415-4ba8-9671-f7343fbf0836` | minúsculas | Tipos STIX 2.1 e UUID v4/v5; sem validar existência do objeto |
| `doi` | `10.1000/292` | preservado | Subconjunto ASCII de DOI; não resolve a publicação |
| `md5` | 32 hexadecimais | minúsculas | Só formato; não confirma que é hash |
| `sha1` | 40 hexadecimais | minúsculas | Só formato; não confirma que é hash |
| `sha256` | 64 hexadecimais | minúsculas | Só formato; não confirma que é hash |
| `cwe` | `CWE-79` | `CWE-79` | Identificador sintático de fraqueza, sem consulta MITRE |
| `capec` | `CAPEC-123` | `CAPEC-123` | Identificador sintático de padrão de ataque |
| `ghsa` | `GHSA-2c3f-gh4j-5m6q` | prefixo em maiúsculas, sufixo minúsculo | Alfabeto GHSA restrito; prefixo GHSA em caixa alta e ID em minúsculas; sem consulta GitHub |
| `attack_group` | `G0016` | `G0016` | Formato de grupo ATT&CK, não atribuição |
| `attack_software` | `S0154` | `S0154` | Formato de software ATT&CK |
| `attack_mitigation` | `M1036` | `M1036` | Formato de mitigação ATT&CK |
| `cve` | `CVE-2024-12345` | `CVE-2024-12345` | Formato e ano 1999–2099; sem consulta CVE.org |
| `attack_technique` | `T1059.001` | `T1059.001` | Sintaxe ATT&CK; não confirma ID existente |
| `attack_tactic` | `TA0001` | `TA0001` | Sintaxe ATT&CK; não confirma ID existente |

## Boas práticas para novos padrões

1. Usar `[0-9]` ao esperar algarismos ASCII, em vez de `\d`.
2. Limitar quantificadores e testar entradas inválidas longas para reduzir o risco de ReDoS.
3. Separar a descoberta de candidato da validação com `ipaddress`, `urllib.parse` ou parser especializado.
4. Preservar `raw` e a posição de origem para auditoria; não modificar o texto de entrada globalmente.
5. Definir exemplos positivos, negativos e limites de escopo em `tests/`.
6. Nunca executar, acessar ou abrir automaticamente URLs e artefatos extraídos.

## Decisões de design e limitações

- Resultados podem se **sobrepor intencionalmente**: um IPv4 presente dentro de uma URL pode aparecer nas duas categorias. Use `--types` para filtrar e `--unique` para deduplicar por (categoria, valor).
- Indicadores neutralizados aceitam padrões simples `[.]`, `[:]` e `hxxp`/`hxxps`. Há diversas outras variantes não cobertas.
- URLs com query strings podem carregar tokens. O extrator não envia dados a serviços externos, mas o operador deve revisar resultados antes de publicá-los.
- IPv6 em notação incomum, caminhos Unicode e e-mails internacionalizados não têm cobertura completa.
- Prefixos privados, de documentação e reservados podem ser extraídos; **extração não significa que o endereço seja roteável ou malicioso**.
- Nunca use regex como única validação de credenciais, dados sensíveis, endereços ou conteúdo hostil.
