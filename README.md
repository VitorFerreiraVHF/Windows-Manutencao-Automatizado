# Windows-Manutencao-Automatizado

Script de automação para manutenção preventiva e corretiva de sistemas Windows. Ideal para técnicos de TI que buscam padronizar e agilizar o processo de limpeza e otimização de máquinas.

## 🚀 Funcionalidades

O script executa uma série de tarefas essenciais, incluindo:

- **Limpeza de Arquivos Temporários:** Limpa pastas `temp`, `%temp%` e `prefetch`.
- **Verificação de Integridade:** Executa `SFC /scannow` e comandos `DISM` para reparar a imagem do sistema.
- **Otimização de Disco:** Limpeza de disco nativa do Windows e desfragmentação (se aplicável).
- **Limpeza de Cache de DNS:** Flush DNS para resolver problemas de conectividade.
- **Remoção de Logs:** Limpeza de logs de eventos antigos para liberar espaço.

## 🛠️ Como Usar

1.  Faça o download do script `.bat` ou `.ps1`.
2.  Clique com o botão direito no arquivo.
3.  Selecione **"Executar como Administrador"** (necessário para comandos de reparo do sistema).
4.  Aguarde a conclusão dos processos e reinicie o computador se solicitado.

## ⚠️ Avisos

- **Uso Profissional:** Este script foi desenvolvido para uso genérico em manutenção de TI.
- **Backup:** Sempre recomendável ter um backup dos dados importantes antes de realizar manutenções de sistema.
- **Compatibilidade:** Testado em Windows 10 e Windows 11.

## 📝 Licença

Este projeto está sob a licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

---

_Desenvolvido para automatizar rotinas de suporte técnico._
