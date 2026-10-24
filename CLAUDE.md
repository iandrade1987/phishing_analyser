# Contexto do projeto (handoff para novo agente/computador)

Ferramenta defensiva de análise de emails de phishing, do Igor Andrade (igor.andrade@bluechip.pt, GitHub: iandrade1987).
Repositório: https://github.com/iandrade1987/phishing_analyser (privado). Branch única: `main`.
O usuário fala português (pt-PT/pt-BR); responda sempre em português, de forma curta.

## Arquivos

- `analisador_email_phishing.html` — versão web, arquivo único, 100% client-side (cole o código-fonte do email ou carregue `.eml`). Tema dark/light.
- `phishing_analyzer.py` — versão CLI (`python phishing_analyzer.py email.eml [--json saida.json]`). `.msg` exige `pip install extract-msg`.
- `README.md` — instalação e uso (com screenshots).

As duas versões implementam a MESMA lógica de heurísticas. Qualquer mudança de regra deve ser feita nas duas.
Ambas são estáticas de propósito: sem requisições de rede (DNS/WHOIS/blacklists), para serem seguras sobre emails maliciosos. Não adicionar chamadas de rede sem o usuário pedir.

## O que já existe

Identificação (From/Reply-To/Return-Path/Message-ID), SPF/DKIM/DMARC, IP de origem, cadeia Received, links suspeitos (encurtadores, IP direto, texto ≠ destino, typosquatting, TLD suspeito), anexos (extensão perigosa, dupla extensão, hashes), palavras-chave de engenharia social, pixel de rastreamento, score 0–100.

IP de origem: primeiro IP público da cadeia Received (salto mais antigo), mais X-Originating-IP / SPF como fontes secundárias. Faixas TEST-NET (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) são tratadas como públicas de propósito, para os emails de exemplo funcionarem.

## Pendências conhecidas

1. **Bug IPv6 nos Received:** a Microsoft escreve IPv6 entre parênteses (`(2a01:111:f403:c200::1)`), mas o parser só reconhece IPv6 entre colchetes. Resultado: o IP aparece com a fonte "SPF/Authentication-Results" em vez de "Received". Corrigir em `parse_received_chain` / `determine_origin` (Python) e `parseReceivedChain` / `determineOrigin` (HTML).
2. **`::1` não deve ser candidato** a IP de origem (é loopback; aparece em `Received: from X (::1) by Y`).
3. Quando o IP de origem for de infraestrutura conhecida (ex.: `*.outbound.protection.outlook.com`), avisar que é o servidor do provedor e não o dispositivo do remetente. Ideia, ainda não pedida.
4. Consulta de reputação/geolocalização do IP: só se o usuário pedir (quebra a regra de "sem rede").

## Ambiente do usuário (Windows 11)

- `gh` CLI NÃO está instalado; o push funciona via `git push` HTTPS normal. Para criar repositórios o usuário os cria no GitHub e passa a URL.
- Sem identidade git global; usar configuração local do repo (`user.name "Igor Andrade"`, `user.email igor.andrade@bluechip.pt`).
- Commits terminam com `Co-Authored-By: Claude ... <noreply@anthropic.com>`.
- Só fazer commit/push quando o usuário pedir.
- Teste da versão web: abrir o HTML no navegador, usar o botão "carregar exemplo suspeito". No preview embutido do Claude (URL `data:`) `crypto.subtle` não existe, então o hash SHA-256 de anexos fica vazio — é esperado.
- Existe também um artifact publicado da versão web no claude.ai (desatualizado: não tem o IP de origem). Republicar só se o usuário pedir.

## Cuidado

Nunca colar emails reais com dados sensíveis em arquivos do repositório. O repo é privado, mas os exemplos devem ser sintéticos.
