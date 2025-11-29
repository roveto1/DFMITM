# DFMITM
Experimento do ataque Man-In-The-Middle no algoritmo de Diffie-Hellman.
Cada branch deste repositório representa uma das máquinas da rede.

A simulação requer que 3 máquinas estejam em uma mesma rede local, onde Alice e Bob tentam criar uma sessão de chat enquanto Mallory tenta atacar por MITM.

Detalhes sobre este trabalho pode ser encontrada no relatório na branch main.

Os scripts precisam da biblioteca cryptography para funcionarem corretamente.

---
Mallory deve envenenar as tabelas ARP de Alice e Bob pelo método de ARP Spoofing. Para fazer isso no linux, usam-se os seguintes comandos:
```bash
sudo arpspoof -i wlan0 -t <IPv4_DE_ALICE> <IPv4_DE_BOB>
sudo arpspoof -i wlan0 -t <IPv4_DE_BOB> <IPv4_DE_ALICE>
```
> Deve ser executado na máquina de Mallory

Além disso, deve-se redirecionar os pacotes da porta 5000 para a porta de Mallory. Para isso, execute isso na máquina de Mallory (Linux):
```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 5000 -j REDIRECT --to-port 5000
```

