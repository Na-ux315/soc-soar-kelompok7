---
date_created: 2026-06-02T02:14
date_modified: 2026-06-02T11:58
---

# Connection

Wazuh Manager:

```bash
ssh -i ~/.ssh/wazuh-manager.pem azureuser@20.6.107.168
```

Victim:

```bash
ssh -i ~/.ssh/wazuh-victim.pem -L 3001:localhost:3001 azureuser@4.145.83.62
```

Attacker:

```bash
ssh -i ~/.ssh/wazuh-attacker.pem azureuser@172.188.9.210
```

---

## Paths

Suricata config: 

```bash
sudo vim /etc/suricata/suricata.yaml
```

Suricata custom rules: 
bash

```bash
sudo vim /var/lib/suricata/rules/local.rules
```

Suricata events: 

```bash
sudo vim /var/log/suricata/eve.json
```

Wazuh agent config: 

```bash
sudo vim /var/ossec/etc/ossec.conf
```

Wazuh manager config: 

```bash
sudo vim /var/ossec/etc/ossec.conf
```

Wazuh alerts: `

```bash
sudo vim /var/ossec/logs/alerts/alerts.json
```

---

# Configuring Wazuh Manager & Agent Configurations

Changing the overall configuration of Wazuh Manager/Agent:

```bash
sudo vim /var/ossec/etc/ossec.conf
```

Restarting Wazuh Manage/Agentr:

```bash
sudo systemctl restart wazuh-manager
```

----

# Configuring Suricata

Changing the local rules of Suricata on Wazuh Agent Victim:

```bash
sudo vim /var/lib/suricata/rules/local.rules
```

Test the Suricata configuration file:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
```

Restart the Suricata service each time there are configuration changes:

```bash 
sudo systemctl restart suricata
```

---

# Connecting to Shuffle

Setting up SSH tunnel for Shuffle UI on Victim: 

```bash
ssh -i ~/.ssh/wazuh-victim.pem -L 3001:localhost:3001 azureuser@4.145.83.62
```

Admin Account:

```text
username: admin
password: adminadmin
```
