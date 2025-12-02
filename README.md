---

# **ELK Installation Guide (Ubuntu)**

This guide explains how to install and configure **Elasticsearch**, **Logstash**, and **Kibana** on Ubuntu.

---

## 📌 **1. Install Java**

```bash
sudo apt update
sudo apt install default-jre default-jdk -y

# Verify installation
java -version
javac --version
```

---

## 📌 **2. Add Elasticsearch GPG Key & Repository**

```bash
# Import Elasticsearch GPG key
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -

# Add Elastic repository (version 7.x)
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list

sudo apt update
```

---

## 📌 **3. Install Elasticsearch**

```bash
sudo apt install elasticsearch -y
```

---

## 📌 **4. Configure Elasticsearch**

```bash
cd /etc/elasticsearch
sudo vim elasticsearch.yml
```

Modify the following:

```
network.host: <my_server_ip>
http.port: 9200
discovery.type: single-node
cluster.name: my-elk-cluster
node.name: node-1
```

---

## 📌 **5. Set JVM Options (RAM usage)**

```bash
sudo vim /etc/elasticsearch/jvm.options
```

Set:

```
-Xms512m
-Xmx512m
```

---

## 📌 **6. Start Elasticsearch Service**

```bash
sudo systemctl start elasticsearch
sudo systemctl enable elasticsearch
sudo systemctl status elasticsearch
```

---

## 📌 **7. Test Elasticsearch**

```bash
curl -X GET "http://<my_server_ip>:9200"
```

---

## 📌 **8. Install Logstash**

```bash
sudo apt install logstash -y
```

---

## 📌 **9. Start Logstash**

```bash
sudo systemctl start logstash
sudo systemctl enable logstash
```

---

## 📌 **10. Create a Test Logstash Pipeline**

```bash
sudo vim /etc/logstash/conf.d/test-pipeline.conf
```

Paste:

```
input {
  file {
    path => "/var/log/syslog"
    start_position => "beginning"
    sincedb_path => "/dev/null"
  }
}

filter {
  grok {
    match => { "message" => "%{SYSLOGLINE}" }
  }
  date {
    match => [ "timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "syslog-%{+YYYY.MM.dd}"
  }
  stdout { codec => rubydebug }
}
```

Restart Logstash:

```bash
sudo systemctl restart logstash
```

---

## 📌 **11. Install Kibana**

```bash
sudo apt install kibana -y
```

---

## 📌 **12. Configure Kibana**

```bash
cd /etc/kibana
sudo vim kibana.yml
```

Set:

```
server.port: 5601
server.host: "<my_server_ip>"
elasticsearch.hosts: ["http://<my_server_ip>:9200"]
```

---

## 📌 **13. Start Kibana**

```bash
sudo systemctl restart kibana
sudo systemctl enable kibana
sudo systemctl status kibana
```

---

## 📌 **14. Access Kibana Dashboard**

Open in browser:

```
http://<my_server_ip>:5601
```

Kibana UI should now appear.

---
