# Nottina Shield — Console de Operações (PoC)
## Sprint A — Políticas
Rotas independentes: /app/policies. Metadados obrigatórios: cliente, ASN, prefixo, POP, ingresso, justificativa, ticket, responsável e TTL 60-86400 segundos. Filtros de pacotes gerados exclusivamente por build_rule existente; guarda PoC: 203.0.113.0/24, origem opcional 198.18.0.0/24, interface ens3.
SQLite mantém policies_v2 e policy_events_v2; ações registram versões imutáveis do ciclo de vida. Conflitos impedem dois DROPs equivalentes no mesmo destino, protocolo, porta e origem sobreposta (conservador).
TTL checado por worker a cada 15s, removendo a regra no dataplane quando presente. Se o serviço cair ou não alcançar o mitigador, a expiração poderá atrasar; não há garantia rígida enquanto o plano de controle estiver indisponível.
Após reboot/flush nftables, a política entra em `missing`, não é reinstalada silenciosamente. O operador usa `Reconstruir`. Políticas expiradas não são restauradas automaticamente. As regras legadas são somente leitura para a camada V2.

## Sprint B — Observabilidade
/app/traffic lê contadores de kernel do Shield em ens3 e ens4 via SSH e sysfs. Calcula Gbps/Mpps de RX ens3 e Gbps TX ens4 com delta de duas amostras distintas. Conserva 24h no SQLite.
O contador de DROP mantém origem nftables e natureza acumulativa. Não é fornecida falsa métrica PASS, pois TX de interface não equivale necessariamente a entrega de tráfego protegido. Também não há classificação real por vetor nesta versão.

## Sprint C — Cobertura e contingência
/app/coverage registra matriz declaratória prefixo→ingresso→POP→mitigador, BGP e bypass com estado inicial unknown; UP/DOWN/INLINE/BYPASS são declarações do operador, não sondagens.
A página /app/resilience simula mudança de caminho A/B usando a matriz cadastrada. Essa simulação **não altera BGP** nem comprova continuidade de serviço. Ensaios reais de adjacências, bypass físico, 100GbE, QinQ/VLAN/MPLS e falhas de hardware continuam fora do EVE-NG.

## Deploy
O serviço continua stdlib-only para a aplicação. No EVE-NG:
```bash
cd /opt/nottina-shield
git pull --ff-only origin main
python3 -m py_compile app.py engineering.py
python3 -m unittest discover -s tests -v
systemctl restart nottina-shield.service
sleep 2
systemctl status nottina-shield.service --no-pager -l
curl -fsS http://127.0.0.1:8787/ -o /tmp/nottina-shield-response.html
journalctl -u nottina-shield -n 60 --no-pager
```
Para rollback, use o commit anterior somente com procedimento de manutenção e backup do SQLite; não reverta scripts sem avaliar as políticas ativas no kernel.

## Limites críticos
- O SQLite com conexão direta e chamadas nft não constitui engine distribuído.
- O cadastro de cobertura não verifica fisicamente o ingresso nem sessões BGP.
- Os dois ingressos são apenas simulação funcional de decisão/cobertura.
- Contadores de interface não têm filtro por cliente, prefixo ou VLAN.
- Após crash entre execução nft e transação SQLite pode restar uma regra órfã; confira o inventário nft e a trilha de auditoria.
- As funcionalidades não estão homologadas para operação comercial, nem executaram testes de falha física ou desempenho.
