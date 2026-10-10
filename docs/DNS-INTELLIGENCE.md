# DNS Intelligence: parser + grafo

## O que suporta

Parser de **um registro DNS por linha**, no formato `FQDN [TTL] [IN] TYPE RDATA`, aceita `IN TTL` e `TTL IN` e nomes ASCII absolutos terminados opcionalmente em ponto.

Registros: `A`, `AAAA`, `NS`, `MX`, `CNAME`, `PTR`, `TXT`. TXT somente políticas `v=spf1` e `v=DMARC1; p=...` por padrão. Outras strings TXT requerem `--include-txt`, pois podem conter verificações de domínio.

Não é parser geral de BIND, não interpreta `$ORIGIN`, registros com múltiplas linhas, nomes relativos, macros, escapes avançados nem resultados de `dig`. Política SPF/DMARC é *reconhecida*, não avaliada pela rede.

## Comandos reproduzíveis

```bash
python3 dns_osint.py parse examples/sample_dns.zone > /tmp/records.jsonl
python3 dns_osint.py graph /tmp/records.jsonl > /tmp/graph.json
python3 evidence_manifest.py examples/sample_dns.zone
python3 -m unittest discover -s tests -v
```

Para não exportar TXT arbitrário, `--include-txt` é opt-in.

## Semântica do grafo

- Nós `domain:<fqdn>` e `ip:<ip>`.
- Relações `dns_a`, `dns_aaaa`, `dns_ns`, `dns_mx`, `dns_cname`, `dns_ptr`.
- Arestas contêm `evidence: [{source, line}]`, deduplicando fontes repetidas.
- **As arestas representam afirmações feitas nos arquivos, não registros DNS atuais.** Não significam propriedade, atribuição, existência ou reputação.
- TXT SPF/DMARC são mantidos nos registros, mas não originam relações de rede automaticamente.

## Limites e cuidados

O parser nunca envia tráfego à rede. `--max-line-length` e `--max-records` limitam o processamento; linhas malformadas são ignoradas com aviso, sem vazamento de conteúdo. Evite publicar arquivos brutos: TXT, caminhos e destinos DMARC podem conter informações particulares. O manifesto usa tamanho e tempo de modificação do sistema de arquivos, **não prova origem nem integridade histórica**.

Referências: [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035), [RFC 7208](https://www.rfc-editor.org/rfc/rfc7208), [RFC 7489](https://www.rfc-editor.org/rfc/rfc7489), [Python ipaddress](https://docs.python.org/3/library/ipaddress.html).
