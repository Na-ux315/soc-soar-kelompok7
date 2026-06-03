# Implementasi SIEM dan SOAR untuk Deteksi dan Mitigasi Serangan DDoS

## Anggota Kelompok

| Nama | NRP |
|--------|--------|
|Jonathan Zelig Sutopo | 5027241047 |
| Adiwidya Budi Pratama | 5027241012 |
| Fika Arka Nuriyah | 5027241071 |
| Naila Cahyarani Idelia | 5027241063 |

---

Proyek ini merupakan pengembangan dari infrastruktur SIEM yang telah dibangun pada mata kuliah MIKS dengan menambahkan kemampuan SOAR (Security Orchestration, Automation, and Response).

Sistem dirancang untuk mendeteksi serangan Distributed Denial of Service (DDoS) secara otomatis menggunakan Suricata dan Wazuh, kemudian menjalankan tindakan mitigasi secara otomatis melalui workflow SOAR.

---

## Arsitektur Sistem

```text
Attacker VM
     |
     v
Victim VM
(Suricata + Wazuh Agent)
     |
     v
Wazuh Manager
(SIEM)
     |
     v
Shuffle SOAR
     |
     v
Automated Response
```

## Komponen Sistem

| Komponen | Fungsi |
|-----------|---------|
| Wazuh Manager | Analisis dan korelasi log |
| Wazuh Agent | Mengirimkan log ke manager |
| Suricata IDS | Mendeteksi aktivitas jaringan mencurigakan |
| Shuffle SOAR | Menjalankan workflow otomatis |
| Attacker VM | Simulasi serangan DDoS |
| Victim VM | Target serangan |

- wazuh-manager  → Publik: 20.6.107.168   | Privat: 10.0.0.4
- wazuh-agent1   → Publik: 4.145.83.62    | Privat: 10.0.0.5
- wazuh-agent2   → Publik: 172.188.9.210  | Privat: 10.0.0.6

URL      : https://20.6.107.168

User     : admin

Password : a.fCWIcbgs8Kag+RsZumqrsqVp*wXRd7

---

## Teknologi yang Digunakan

| Teknologi | Fungsi |
|-----------|---------|
| Wazuh | Security Information and Event Management (SIEM) untuk monitoring, analisis, dan korelasi log |
| Suricata | Intrusion Detection System (IDS) untuk mendeteksi aktivitas jaringan yang mencurigakan dan serangan DDoS |
| Shuffle | Security Orchestration, Automation, and Response (SOAR) untuk mengotomatisasi workflow respons insiden |
| Ubuntu Server | Sistem operasi yang digunakan pada seluruh virtual machine |
| Microsoft Azure | Platform cloud untuk deployment infrastruktur dan virtual machine |

---

## Alur Kerja Sistem

1. Attacker mengirimkan trafik DDoS ke Victim VM.
2. Suricata mendeteksi pola trafik yang mencurigakan.
3. Event dikirim ke Wazuh Agent.
4. Wazuh Manager melakukan korelasi menggunakan custom rule.
5. Alert DDoS dibuat.
6. Alert diteruskan ke Shuffle SOAR.
7. Workflow SOAR dijalankan secara otomatis.
8. Sistem melakukan mitigasi terhadap sumber serangan.

---

## Implementasi Deteksi DDoS

Beberapa jenis serangan yang diuji:

- 
- 
- 

Deteksi dilakukan menggunakan custom rule pada Wazuh yang memanfaatkan parameter:

- 
- 
- 

---

## Implementasi SOAR

Platform Shuffle digunakan untuk:

- 
- 
- 

---

## Pengujian

- *(Jenis serangan yang diuji)*

```bash

```

- *(Jenis serangan yang diuji)*

```bash

```

- *(Jenis serangan yang diuji)*

```bash

```

---

## Hasil Pengujian

| Pengujian | Hasil |
|-----------|--------|
| Integrasi Suricata | Berhasil/Gagal |
| Integrasi Wazuh | Berhasil/Gagal |
| Deteksi DDoS | Berhasil/Gagal |
| Workflow SOAR | Berhasil/Gagal |
| Mitigasi Otomatis | Berhasil/Gagal |

---

## Dokumentasi

### Topologi Sistem

*(Tambahkan gambar arsitektur di sini)*

### Alert DDoS pada Wazuh

*(Tambahkan screenshot dashboard Wazuh di sini)*

### Workflow Shuffle

*(Tambahkan screenshot workflow Shuffle di sini)*

### Hasil Mitigasi

*(Tambahkan screenshot hasil blocking atau response otomatis di sini)*

---

## Kesimpulan

Integrasi Wazuh SIEM dan Shuffle SOAR berhasil diterapkan untuk mendeteksi serta merespons serangan DDoS secara otomatis. Sistem mampu melakukan monitoring, korelasi log, pembuatan alert, dan mitigasi insiden tanpa intervensi manual sehingga meningkatkan efektivitas proses keamanan siber.

---

# Cybersecurity Infrastructure System

---

type: project-hub

tags:

status: In Progress

tech_stack: []

repo_url: 

date_created: 2026-05-20T15:33

date_modified: 2026-06-02T08:25

---

## Project Overview / Objectives

```xml
<!-- Local rules -->

<!-- Modify it at your will. -->
<!-- Copyright (C) 2015, Wazuh Inc. -->

<!-- Example -->
<group name="local,syslog,sshd,">

  <!--
  Dec 10 01:02:02 host sshd[1234]: Failed none for root from 1.1.1.1 port 1066 ssh2
  -->
  <rule id="100001" level="5">
    <if_sid>5716</if_sid>
    <srcip>1.1.1.1</srcip>
    <description>sshd: authentication failed from IP 1.1.1.1.</description>
    <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>

  <rule id="100015" level="10">
      <if_sid>86601</if_sid>
      <field name="alert.signature_id">^1000001$|^1000002$</field>
      <description>DDoS Attack Signature Triggered: Volumetric Network Flooding Detected.</description>
      <mitre>                                                                                      <id>T1498</id>
      </mitre>
  </rule>

</group>

<!-- DDoS Detection Rules — matches Suricata EVE JSON fields via data.* -->
<!-- Wazuh frequency tag: fires rule after N events in <timeframe> seconds from same src_ip -->

<group name="ddos,suricata,">

  <!-- Rule 100001: Suricata IDS alert received — base rule for all alert events -->
  <!-- Matches any EVE line where event_type=alert → parent for flood rules -->
  <rule id="100001" level="5">
    <decoded_as>json</decoded_as>
    <field name="data.event_type">alert</field>
    <description>Suricata IDS Alert detected on $(agent.name)</description>
    <group>ids,suricata_alert,</group>
  </rule>

  <!-- Rule 100002: SYN Flood detection -->
  <!-- Mechanism: hping3 --syn floods target with TCP SYN, never completes handshake -->
  <!-- Suricata detects via ET DOS rules → event_type:alert, proto:TCP -->
  <!-- frequency 100 in 10s from same src_ip → statistically confirms flood, not scan -->
  <rule id="100002" level="12" frequency="100" timeframe="10">
    <if_matched_sid>100001</if_matched_sid>
    <field name="data.proto">TCP</field>
    <same_field>data.src_ip</same_field>
    <description>Possible SYN Flood Attack from $(data.src_ip) on $(agent.name)</description>
    <group>ddos,syn_flood,</group>
  </rule>

  <!-- Rule 100003: ICMP Flood detection -->
  <!-- Mechanism: hping3 --icmp sends continuous ICMP echo requests at high rate -->
  <!-- Suricata proto field = ICMP on EVE flow/alert events -->
  <rule id="100003" level="12" frequency="100" timeframe="10">
    <if_matched_sid>100001</if_matched_sid>
    <field name="data.proto">ICMP</field>
    <same_field>data.src_ip</same_field>
    <description>Possible ICMP Flood Attack from $(data.src_ip) on $(agent.name)</description>
    <group>ddos,icmp_flood,</group>
  </rule>

  <!-- Rule 100004: UDP Flood detection -->
  <!-- Mechanism: hping3 --udp sends UDP datagrams to random/fixed ports -->
  <!-- Target exhausts resources processing unreachable port responses -->
  <rule id="100004" level="12" frequency="100" timeframe="10">
    <if_matched_sid>100001</if_matched_sid>
    <field name="data.proto">UDP</field>
    <same_field>data.src_ip</same_field>
    <description>Possible UDP Flood Attack from $(data.src_ip) on $(agent.name)</description>
    <group>ddos,udp_flood,</group>
  </rule>

  <!-- Rule 100005: High-volume flow anomaly — fallback if Suricata alert rules don't fire -->
  <!-- Matches event_type:flow directly — no dependency on Suricata ruleset -->
  <!-- Catches flood traffic even if Suricata has no matching IDS signature -->
    <!-- 100005: base rule matches single flow event -->
  <rule id="100005" level="3">
    <decoded_as>json</decoded_as>
    <field name="data.event_type">flow</field>
    <description>Suricata flow event on $(agent.name)</description>
    <group>suricata_flow,</group>
  </rule>

  <!-- 100006: frequency rule counts 200 flows from same src_ip in 10s -->
  <rule id="100006" level="10" frequency="200" timeframe="10">
    <if_matched_sid>100005</if_matched_sid>
    <same_field>data.src_ip</same_field>
    <description>High flow volume anomaly from $(data.src_ip) - possible DDoS on $(agent.name)</description>
    <group>ddos,flow_anomaly,</group>
  </rule>
</group>
```

---

## Active Tasks

> [!todo] Todo List
>
> ```tasks
> not done
> path includes 01_projects/cybersecurity_infrastructure_system
> show backlink
> sort by due
> sort by function task.description.includes('#important') ? 0 : 1
> sort by priority
> sort by created
> ```
