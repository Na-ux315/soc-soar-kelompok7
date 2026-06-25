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

## Arsitektur Deteksi

```
Attacker (Local Machine / Kali WSL2)
        |
        v
Victim VM (20.244.25.231 | Privat: 10.1.0.5)
  - Suricata IDS (custom rules + et/open ruleset)
  - Apache2 (attack surface port 80)
  - OpenSSH (attack surface port 22)
  - Wazuh Agent (forward eve.json ke Manager)
        |
        v
Wazuh Manager (20.244.11.27 | Privat: 10.1.0.4)
  - Decode & korelasi alert Suricata
  - Simpan ke Wazuh Indexer (OpenSearch)
  - Visualisasi di Wazuh Dashboard
```

## Komponen Sistem

| Komponen | Fungsi |
|---|---|
| Wazuh Manager | Decode, korelasi, dan penyimpanan log/alert |
| Wazuh Agent | Membaca eve.json Suricata, forward ke Manager |
| Suricata IDS | Deteksi pola serangan jaringan via custom rules |
| Victim VM | Target simulasi serangan (Apache2, OpenSSH) |
| Attacker (Local) | Sumber simulasi serangan (hping3 via WSL2) |

**Versi:** Wazuh Manager & Agent v4.14.5 (rc1), Suricata 8.0.5

## Custom Rules Suricata — Kriteria Deteksi

Rules didefinisikan secara independen di `/var/lib/suricata/rules/local.rules` pada Victim VM, terdaftar di `suricata.yaml` terpisah dari ruleset bawaan (`et/open`) agar tidak tertimpa saat `suricata-update` dijalankan ulang.

### Kategori DDoS

| SID | Nama Signature | Kriteria Deteksi |
|---|---|---|
| 1000001 | LOCAL DDoS SYN Flood Detected | ≥50 paket SYN dari source IP yang sama dalam 10 detik, ke port manapun |
| 1000002 | LOCAL DDoS SYN Flood to Service Port | ≥30 paket SYN dari source IP yang sama dalam 10 detik, ke port 22/80/21 |
| 1000003 | LOCAL DDoS HTTP Flood Detected | ≥100 HTTP request dari source IP yang sama dalam 10 detik ke port 80 |
| 1000004 | LOCAL DDoS ICMP Flood Detected | ≥50 ICMP echo request dari source IP yang sama dalam 10 detik |
| 1000005 | LOCAL DDoS UDP Flood Detected | ≥100 paket UDP dari source IP yang sama dalam 10 detik |
| 1000006 | LOCAL DDoS Possible Slowloris | ≥80 koneksi TCP established ke port 80 dari source IP yang sama dalam 30 detik |

### Kategori Malware

| SID | Nama Signature | Kriteria Deteksi |
|---|---|---|
| 1000010 | LOCAL Malware Possible SSH Brute Force Attempt | ≥10 percobaan koneksi ke port 22 dari source IP yang sama dalam 30 detik |
| 1000011 | LOCAL Malware Possible Metasploit Reverse Shell Outbound | Koneksi outbound dari Victim ke port 4444 (default Metasploit handler) |
| 1000012 | LOCAL Malware Suspicious Outbound to Common Reverse Shell Port | Koneksi outbound ke port 1337/4445/8443/9001 |
| 1000013 | LOCAL Malware Possible FTP Brute Force/Exploit Attempt | ≥10 percobaan koneksi ke port 21 dari source IP yang sama dalam 30 detik |
| 1000014 | LOCAL Malware EICAR Test Signature Detected | Payload mengandung substring `EICAR-STANDARD-ANTIVIRUS-TEST-FILE` |
| 1000015 / 1000016 | LOCAL Malware Suspicious Scanner User-Agent | User-Agent HTTP mengandung kata "Metasploit" atau "Nikto" |

**Catatan rasional threshold:** Nilai ambang (50 paket/10 detik, 100 request/10 detik, dst.) ditentukan berdasarkan asumsi bahwa traffic normal pengguna tunggal tidak akan menghasilkan volume sebesar itu dalam rentang waktu singkat, sementara automated flood tools (hping3, dsb.) secara konsisten melampauinya. Nilai ini dapat dikalibrasi lebih lanjut berdasarkan baseline traffic normal sistem.

## Hasil Pengujian

Pengujian dilakukan dari local attacker machine (WSL2 Ubuntu, tool `hping3` versi 3.0.0-alpha-2) menuju Victim VM publik (20.244.25.231).

| Pengujian | Tool/Method | SID Ter-trigger | Status | Catatan |
|---|---|---|---|---|
| SYN Flood | `hping3 -S -p 80 --flood` | 1000001, 1000002 | ✅ Berhasil | 118.624 paket terkirim; alert tercatat hingga ke Wazuh Manager (331 hits) |
| SSH Brute Force | Loop SSH connection (15x) | 1000010 | ✅ Berhasil | 10 alert tercatat dalam window ~6 detik |
| EICAR Test Signature | `curl` GET request | 1000014 | ✅ Berhasil (setelah revisi) | Percobaan awal dengan string penuh (68 karakter) gagal karena koneksi ter-reset sebelum payload lengkap terkirim; rule disederhanakan menjadi substring unik yang lebih singkat (`rev:2`) dan berhasil terdeteksi |



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
