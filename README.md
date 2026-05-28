# Windows-Manutencao-Automatizado

Script de automação para manutenção preventiva e corretiva de sistemas Windows. Ideal para técnicos de TI que buscam padronizar e agilizar o processo de limpeza e otimização de máquinas.

## 🚀 Funcionalidades

O script executa uma série de tarefas essenciais, incluindo:

- **Identificação do equipamento:** Coleta hostname, usuário, Service Tag, modelo, domínio, versão/build do Windows e uptime.
- **Limpeza de arquivos temporários:** Limpa locais permitidos pelo POP, incluindo `C:\Windows\Temp`, `%TEMP%`, temporários de usuários, cache do Windows Update, caches de navegadores fechados, logs antigos e lixeira.
- **Verificação de disco:** Avalia espaço livre mínimo, executa `chkdsk /scan` e tenta coletar saúde do disco/SMART.
- **Atualizações:** Executa Windows Update via `PSWindowsUpdate`, atualiza drivers Microsoft e usa `winget` para aplicativos catalogados.
- **Segurança:** Valida Windows Defender/antivírus, assinaturas, varredura rápida ou completa, Firewall e BitLocker quando aplicável.
- **Rede e VPN:** Executa flush DNS, valida adaptadores, DNS, HTTPS externo, adaptadores VPN conhecidos e hosts corporativos informados.
- **Performance e estabilidade:** Coleta uso de CPU/memória, itens de inicialização, programas instalados e eventos recentes de erro/travamento.
- **Verificação de integridade:** Executa `DISM /ScanHealth`, `DISM /RestoreHealth` e `SFC /scannow`.
- **Evidência para chamado:** Gera log técnico e um `ResumoCard_*.txt` pronto para copiar no card da demanda.

## 🛠️ Como Usar

1.  Faça o download do script `.bat` ou `.ps1`.
2.  Clique com o botão direito no arquivo.
3.  Selecione **"Executar como Administrador"** (necessário para comandos de reparo do sistema).
4.  Aguarde a conclusão dos processos e reinicie o computador se solicitado.

Também é possível executar com parâmetros:

```powershell
.\Manutencao.ps1 -Silent
.\Manutencao.ps1 -FullDefenderScan -CleanPrefetch -CleanMinidump
.\Manutencao.ps1 -CorporateHosts intranet.empresa.com,portal.empresa.com
```

Ao final, os arquivos são gerados em `Logs`:

- `Manutencao_<Maquina>_<Usuario>_<ServiceTag>_<Data>.log`
- `ResumoCard_<Maquina>_<Usuario>_<ServiceTag>_<Data>.txt`

Para consolidar execuções em Excel:

```powershell
.\Consolidar-Logs.ps1
```

## ⚠️ Avisos

- **Uso Profissional:** Este script foi desenvolvido para uso genérico em manutenção de TI.
- **Backup:** Sempre recomendável ter um backup dos dados importantes antes de realizar manutenções de sistema.
- **Compatibilidade:** Testado em Windows 10 e Windows 11.

## 📝 Licença

Este projeto está sob a licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

---

_Desenvolvido para automatizar rotinas de suporte técnico._
