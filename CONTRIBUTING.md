# Contribuindo

1. Abra uma issue explicando a categoria, o caso de uso OSINT/CTI e as fontes técnicas.
2. Acrescente regex **e** validação semântica quando existir um parser confiável.
3. Adicione ao menos um caso positivo, um negativo e um exemplo de indicador neutralizado, quando aplicável.
4. Execute `python3 -m unittest discover -s tests -v` antes do pull request.
5. Documente limites (e.g. e-mails RFC completos, TLDs, Unicode, falsos positivos).
6. Evite dados pessoais reais, tokens, credenciais e artefatos ativos nos fixtures.

Os exemplos e testes devem ser sintéticos. Não adicione código que consulte ou visite automaticamente os indicadores encontrados.
