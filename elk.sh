#!/bin/bash

################################################################################
# ELK Stack (Elasticsearch, Logstash, Kibana) Installation Script
# For Ubuntu/Debian-based systems
# Purpose: Learning and Testing Environment
################################################################################

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration Variables
SERVER_IP=$(hostname -I | awk '{print $1}')
ES_VERSION="7.x"
ES_PORT="9200"
KIBANA_PORT="5601"
JVM_HEAP="512m"

################################################################################
# Helper Functions
################################################################################

print_message() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root or with sudo"
        exit 1
    fi
}

check_system() {
    print_message "Checking system requirements..."
    
    # Check available memory
    total_mem=$(free -m | awk 'NR==2{print $2}')
    if [ "$total_mem" -lt 2048 ]; then
        print_warning "System has less than 2GB RAM. ELK Stack may run slowly."
        read -p "Continue anyway? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

################################################################################
# Installation Functions
################################################################################

install_java() {
    print_message "Installing Java..."
    apt update -qq
    apt install default-jre default-jdk -y
    
    java_version=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}')
    print_message "Java version installed: $java_version"
}

add_elastic_repo() {
    print_message "Adding Elasticsearch repository..."
    
    # Import GPG key
    curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
    
    # Add repository
    echo "deb https://artifacts.elastic.co/packages/${ES_VERSION}/apt stable main" > /etc/apt/sources.list.d/elastic-${ES_VERSION}.list
    
    apt update -qq
    print_message "Elasticsearch repository added successfully"
}

install_elasticsearch() {
    print_message "Installing Elasticsearch..."
    apt install elasticsearch -y
    
    print_message "Configuring Elasticsearch..."
    
    # Backup original config
    cp /etc/elasticsearch/elasticsearch.yml /etc/elasticsearch/elasticsearch.yml.bak
    
    # Configure elasticsearch.yml
    cat > /etc/elasticsearch/elasticsearch.yml <<EOF
# Cluster Configuration
cluster.name: my-elk-cluster
node.name: node-1

# Network Configuration
network.host: ${SERVER_IP}
http.port: ${ES_PORT}

# Discovery Configuration (Single Node)
discovery.type: single-node

# Path Configuration
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
EOF

    # Configure JVM options
    print_message "Setting JVM heap size to ${JVM_HEAP}..."
    
    # Backup original JVM options
    cp /etc/elasticsearch/jvm.options /etc/elasticsearch/jvm.options.bak
    
    # Update heap size
    sed -i "s/^-Xms.*/-Xms${JVM_HEAP}/" /etc/elasticsearch/jvm.options
    sed -i "s/^-Xmx.*/-Xmx${JVM_HEAP}/" /etc/elasticsearch/jvm.options
    
    # Start and enable Elasticsearch
    systemctl daemon-reload
    systemctl enable elasticsearch
    systemctl start elasticsearch
    
    print_message "Waiting for Elasticsearch to start..."
    sleep 15
    
    # Test Elasticsearch
    if curl -s -X GET "localhost:${ES_PORT}" > /dev/null; then
        print_message "Elasticsearch is running successfully!"
    else
        print_error "Elasticsearch failed to start. Check logs: journalctl -u elasticsearch"
        exit 1
    fi
}

install_logstash() {
    print_message "Installing Logstash..."
    apt install logstash -y
    
    print_message "Creating sample Logstash pipeline configurations..."
    
    # Create directory if not exists
    mkdir -p /etc/logstash/conf.d
    
    # Sample pipeline 1: Syslog
    cat > /etc/logstash/conf.d/01-syslog-pipeline.conf <<'EOF'
input {
  file {
    path => "/var/log/syslog"
    start_position => "beginning"
    sincedb_path => "/var/lib/logstash/sincedb_syslog"
    tags => ["syslog"]
  }
}

filter {
  if "syslog" in [tags] {
    grok {
      match => { "message" => "%{SYSLOGLINE}" }
    }
    date {
      match => [ "timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}

output {
  if "syslog" in [tags] {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "syslog-%{+YYYY.MM.dd}"
    }
  }
}
EOF

    # Sample pipeline 2: Test input
    cat > /etc/logstash/conf.d/02-test-pipeline.conf <<'EOF'
input {
  stdin {
    tags => ["test"]
  }
}

filter {
  if "test" in [tags] {
    mutate {
      add_field => { "environment" => "test" }
    }
  }
}

output {
  if "test" in [tags] {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "test-logs-%{+YYYY.MM.dd}"
    }
    stdout { codec => rubydebug }
  }
}
EOF

    # Start and enable Logstash
    systemctl enable logstash
    systemctl start logstash
    
    print_message "Logstash installed and started"
}

install_kibana() {
    print_message "Installing Kibana..."
    apt install kibana -y
    
    print_message "Configuring Kibana..."
    
    # Backup original config
    cp /etc/kibana/kibana.yml /etc/kibana/kibana.yml.bak
    
    # Configure kibana.yml
    cat > /etc/kibana/kibana.yml <<EOF
# Server Configuration
server.port: ${KIBANA_PORT}
server.host: "${SERVER_IP}"

# Elasticsearch Configuration
elasticsearch.hosts: ["http://${SERVER_IP}:${ES_PORT}"]

# Kibana Configuration
kibana.index: ".kibana"
EOF

    # Start and enable Kibana
    systemctl enable kibana
    systemctl start kibana
    
    print_message "Waiting for Kibana to start..."
    sleep 20
    
    print_message "Kibana installed and started"
}

create_sample_data() {
    print_message "Creating sample data for testing..."
    
    # Wait for Elasticsearch to be fully ready
    sleep 5
    
    # Create sample index with test data
    curl -s -X POST "localhost:${ES_PORT}/test-index/_doc/1" -H 'Content-Type: application/json' -d'
{
  "user": "john_doe",
  "message": "First test message",
  "timestamp": "2025-12-02T10:00:00",
  "level": "info"
}' > /dev/null

    curl -s -X POST "localhost:${ES_PORT}/test-index/_doc/2" -H 'Content-Type: application/json' -d'
{
  "user": "jane_smith",
  "message": "Second test message",
  "timestamp": "2025-12-02T10:05:00",
  "level": "warning"
}' > /dev/null

    curl -s -X POST "localhost:${ES_PORT}/test-index/_doc/3" -H 'Content-Type: application/json' -d'
{
  "user": "admin",
  "message": "System initialization complete",
  "timestamp": "2025-12-02T10:10:00",
  "level": "info"
}' > /dev/null

    # Create CSV sample data
    cat > /tmp/sample.csv <<EOF
id,name,age,city,department
1,Alice Johnson,30,New York,Engineering
2,Bob Smith,25,Los Angeles,Marketing
3,Charlie Brown,35,Chicago,Sales
4,Diana Prince,28,Boston,HR
5,Eve Wilson,32,Seattle,Engineering
EOF

    print_message "Sample data created successfully"
}

create_helper_scripts() {
    print_message "Creating helper scripts..."
    
    # Create start script
    cat > /usr/local/bin/elk-start <<'EOF'
#!/bin/bash
echo "Starting ELK Stack..."
systemctl start elasticsearch
sleep 10
systemctl start logstash
systemctl start kibana
echo "ELK Stack started"
EOF
    chmod +x /usr/local/bin/elk-start
    
    # Create stop script
    cat > /usr/local/bin/elk-stop <<'EOF'
#!/bin/bash
echo "Stopping ELK Stack..."
systemctl stop kibana
systemctl stop logstash
systemctl stop elasticsearch
echo "ELK Stack stopped"
EOF
    chmod +x /usr/local/bin/elk-stop
    
    # Create status script
    cat > /usr/local/bin/elk-status <<'EOF'
#!/bin/bash
echo "=== ELK Stack Status ==="
echo ""
echo "Elasticsearch:"
systemctl status elasticsearch --no-pager -l | head -n 3
echo ""
echo "Logstash:"
systemctl status logstash --no-pager -l | head -n 3
echo ""
echo "Kibana:"
systemctl status kibana --no-pager -l | head -n 3
EOF
    chmod +x /usr/local/bin/elk-status
    
    # Create test script
    cat > /usr/local/bin/elk-test <<EOF
#!/bin/bash
echo "=== Testing ELK Stack ==="
echo ""
echo "1. Elasticsearch Health:"
curl -s -X GET "localhost:${ES_PORT}/_cluster/health?pretty" | grep -E "status|number_of_nodes"
echo ""
echo "2. Elasticsearch Indices:"
curl -s -X GET "localhost:${ES_PORT}/_cat/indices?v"
echo ""
echo "3. Sample Query:"
curl -s -X GET "localhost:${ES_PORT}/test-index/_search?pretty" | head -n 20
echo ""
echo "Access Kibana at: http://${SERVER_IP}:${KIBANA_PORT}"
EOF
    chmod +x /usr/local/bin/elk-test
    
    print_message "Helper scripts created: elk-start, elk-stop, elk-status, elk-test"
}

display_summary() {
    echo ""
    echo "================================================================================"
    echo -e "${GREEN}ELK Stack Installation Complete!${NC}"
    echo "================================================================================"
    echo ""
    echo "Service Information:"
    echo "  - Elasticsearch: http://${SERVER_IP}:${ES_PORT}"
    echo "  - Kibana:        http://${SERVER_IP}:${KIBANA_PORT}"
    echo ""
    echo "Configuration Files:"
    echo "  - Elasticsearch: /etc/elasticsearch/elasticsearch.yml"
    echo "  - Logstash:      /etc/logstash/conf.d/"
    echo "  - Kibana:        /etc/kibana/kibana.yml"
    echo ""
    echo "Helper Commands:"
    echo "  - elk-start   : Start all ELK services"
    echo "  - elk-stop    : Stop all ELK services"
    echo "  - elk-status  : Check status of all services"
    echo "  - elk-test    : Test ELK stack and show sample data"
    echo ""
    echo "Quick Test:"
    echo "  curl -X GET 'localhost:${ES_PORT}/_cluster/health?pretty'"
    echo "  curl -X GET 'localhost:${ES_PORT}/_cat/indices?v'"
    echo ""
    echo "Next Steps:"
    echo "  1. Access Kibana at http://${SERVER_IP}:${KIBANA_PORT}"
    echo "  2. Create index patterns in Kibana (Management → Index Patterns)"
    echo "  3. Explore logs in Discover section"
    echo "  4. Create visualizations and dashboards"
    echo ""
    echo "Sample Data Location: /tmp/sample.csv"
    echo ""
    echo "================================================================================"
}

################################################################################
# Main Installation Flow
################################################################################

main() {
    clear
    echo "================================================================================"
    echo "              ELK Stack Installation Script"
    echo "         Elasticsearch, Logstash, Kibana (Version ${ES_VERSION})"
    echo "================================================================================"
    echo ""
    
    check_root
    check_system
    
    print_message "Server IP detected: ${SERVER_IP}"
    print_message "Starting installation..."
    echo ""
    
    install_java
    add_elastic_repo
    install_elasticsearch
    install_logstash
    install_kibana
    create_sample_data
    create_helper_scripts
    
    display_summary
    
    print_message "Installation log saved to: /var/log/elk-installation.log"
}

# Run main installation
main 2>&1 | tee /var/log/elk-installation.log
