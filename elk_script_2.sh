#!/bin/bash

################################################################################
# ELK Stack (Elasticsearch, Logstash, Kibana) Installation Script
# WITH SECURITY (X-Pack) AND DEMO DASHBOARD
# For Ubuntu/Debian-based systems
################################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
SERVER_IP=$(hostname -I | awk '{print $1}')
ES_VERSION="7.x"
ES_PORT="9200"
KIBANA_PORT="5601"
JVM_HEAP="512m"
ELASTIC_PASSWORD=""

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

print_section() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root or with sudo"
        exit 1
    fi
}

check_system() {
    print_message "Checking system requirements..."
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
    print_section "Installing Java"
    apt update -qq
    apt install default-jre default-jdk -y
    java_version=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}')
    print_message "Java version installed: $java_version"
}

add_elastic_repo() {
    print_section "Adding Elasticsearch Repository"
    curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
    echo "deb https://artifacts.elastic.co/packages/${ES_VERSION}/apt stable main" > /etc/apt/sources.list.d/elastic-${ES_VERSION}.list
    apt update -qq
}

install_elasticsearch() {
    print_section "Installing Elasticsearch with Security"
    apt install elasticsearch -y
    
    # Backup original config
    cp /etc/elasticsearch/elasticsearch.yml /etc/elasticsearch/elasticsearch.yml.bak
    
    # Configure with security enabled
    cat > /etc/elasticsearch/elasticsearch.yml <<EOF
cluster.name: my-elk-cluster
node.name: node-1
network.host: ${SERVER_IP}
http.port: ${ES_PORT}
discovery.type: single-node
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch

# Security Settings
xpack.security.enabled: true
xpack.security.authc.api_key.enabled: true
EOF

    # Configure JVM
    cp /etc/elasticsearch/jvm.options /etc/elasticsearch/jvm.options.bak
    sed -i "s/^-Xms.*/-Xms${JVM_HEAP}/" /etc/elasticsearch/jvm.options
    sed -i "s/^-Xmx.*/-Xmx${JVM_HEAP}/" /etc/elasticsearch/jvm.options
    
    # Start Elasticsearch
    systemctl daemon-reload
    systemctl enable elasticsearch
    systemctl start elasticsearch
    
    print_message "Waiting for Elasticsearch to start..."
    sleep 20
}

setup_elasticsearch_security() {
    print_section "Setting Up Elasticsearch Security"
    
    # Generate passwords automatically
    print_message "Generating passwords for built-in users..."
    
    # Set passwords using elasticsearch-setup-passwords
    cd /usr/share/elasticsearch/bin
    
    # Use auto mode to generate random passwords
    password_output=$(yes | ./elasticsearch-setup-passwords auto 2>&1)
    
    # Extract elastic user password
    ELASTIC_PASSWORD=$(echo "$password_output" | grep "PASSWORD elastic" | awk '{print $NF}')
    KIBANA_PASSWORD=$(echo "$password_output" | grep "PASSWORD kibana_system" | awk '{print $NF}')
    
    # Save passwords to file
    cat > /root/elk-passwords.txt <<EOF
===========================================
ELK Stack Passwords
===========================================
Generated on: $(date)

Elasticsearch URL: http://${SERVER_IP}:${ES_PORT}
Kibana URL: http://${SERVER_IP}:${KIBANA_PORT}

elastic user password: ${ELASTIC_PASSWORD}
kibana_system password: ${KIBANA_PASSWORD}

Login to Kibana with:
Username: elastic
Password: ${ELASTIC_PASSWORD}
===========================================
EOF
    
    chmod 600 /root/elk-passwords.txt
    
    print_message "Passwords saved to: /root/elk-passwords.txt"
    print_warning "IMPORTANT: Save these passwords securely!"
    echo ""
    cat /root/elk-passwords.txt
    echo ""
    
    # Test connection
    sleep 5
    if curl -s -u elastic:${ELASTIC_PASSWORD} -X GET "localhost:${ES_PORT}" > /dev/null; then
        print_message "Elasticsearch security configured successfully!"
    else
        print_error "Failed to authenticate with Elasticsearch"
        exit 1
    fi
}

install_logstash() {
    print_section "Installing Logstash"
    apt install logstash -y
    
    mkdir -p /etc/logstash/conf.d
    
    # Logstash pipeline with authentication
    cat > /etc/logstash/conf.d/01-demo-pipeline.conf <<EOF
input {
  file {
    path => "/var/log/syslog"
    start_position => "beginning"
    sincedb_path => "/var/lib/logstash/sincedb_syslog"
    tags => ["syslog"]
  }
  
  heartbeat {
    interval => 10
    type => "heartbeat"
    tags => ["heartbeat"]
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
  
  if "heartbeat" in [tags] {
    mutate {
      add_field => { 
        "status" => "alive"
        "component" => "logstash"
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["${SERVER_IP}:${ES_PORT}"]
    user => "elastic"
    password => "${ELASTIC_PASSWORD}"
    index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
  }
}
EOF

    systemctl enable logstash
    systemctl start logstash
}

install_kibana() {
    print_section "Installing Kibana"
    apt install kibana -y
    
    cp /etc/kibana/kibana.yml /etc/kibana/kibana.yml.bak
    
    cat > /etc/kibana/kibana.yml <<EOF
server.port: ${KIBANA_PORT}
server.host: "${SERVER_IP}"
elasticsearch.hosts: ["http://${SERVER_IP}:${ES_PORT}"]
elasticsearch.username: "kibana_system"
elasticsearch.password: "${KIBANA_PASSWORD}"
kibana.index: ".kibana"
EOF

    systemctl enable kibana
    systemctl start kibana
    
    print_message "Waiting for Kibana to start..."
    sleep 25
}

create_demo_data() {
    print_section "Creating Demo Data"
    
    # Create sample application logs
    cat > /tmp/generate-demo-logs.sh <<'LOGSCRIPT'
#!/bin/bash
while true; do
  LEVEL=("INFO" "WARNING" "ERROR" "DEBUG")
  COMPONENT=("web-server" "database" "cache" "api" "auth")
  USER=("alice" "bob" "charlie" "admin" "guest")
  
  RANDOM_LEVEL=${LEVEL[$RANDOM % ${#LEVEL[@]}]}
  RANDOM_COMPONENT=${COMPONENT[$RANDOM % ${#COMPONENT[@]}]}
  RANDOM_USER=${USER[$RANDOM % ${#USER[@]}]}
  
  echo "{\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)\",\"level\":\"$RANDOM_LEVEL\",\"component\":\"$RANDOM_COMPONENT\",\"user\":\"$RANDOM_USER\",\"message\":\"Sample log message from $RANDOM_COMPONENT\"}"
  
  sleep 5
done
LOGSCRIPT
    
    chmod +x /tmp/generate-demo-logs.sh
    
    # Create system metrics data
    for i in {1..50}; do
        timestamp=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
        cpu_usage=$((RANDOM % 100))
        memory_usage=$((RANDOM % 100))
        disk_usage=$((RANDOM % 100))
        
        curl -s -u elastic:${ELASTIC_PASSWORD} -X POST "localhost:${ES_PORT}/system-metrics/_doc" \
        -H 'Content-Type: application/json' -d"{
          \"@timestamp\": \"$timestamp\",
          \"host\": \"demo-server\",
          \"cpu_percent\": $cpu_usage,
          \"memory_percent\": $memory_usage,
          \"disk_percent\": $disk_usage,
          \"status\": \"running\"
        }" > /dev/null
    done
    
    # Create application logs
    LEVELS=("INFO" "WARNING" "ERROR" "DEBUG")
    COMPONENTS=("web-server" "database" "cache" "api" "auth")
    MESSAGES=("Request processed successfully" "Connection timeout" "Database query slow" "Cache miss" "Authentication failed" "New user registered" "File uploaded" "API rate limit exceeded")
    
    for i in {1..100}; do
        timestamp=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
        level=${LEVELS[$RANDOM % ${#LEVELS[@]}]}
        component=${COMPONENTS[$RANDOM % ${#COMPONENTS[@]}]}
        message=${MESSAGES[$RANDOM % ${#MESSAGES[@]}]}
        response_time=$((RANDOM % 1000))
        
        curl -s -u elastic:${ELASTIC_PASSWORD} -X POST "localhost:${ES_PORT}/app-logs/_doc" \
        -H 'Content-Type: application/json' -d"{
          \"@timestamp\": \"$timestamp\",
          \"level\": \"$level\",
          \"component\": \"$component\",
          \"message\": \"$message\",
          \"response_time_ms\": $response_time
        }" > /dev/null
    done
    
    # Create user activity data
    USERS=("alice@example.com" "bob@example.com" "charlie@example.com" "admin@example.com")
    ACTIONS=("login" "logout" "view_page" "download" "upload" "delete" "update")
    
    for i in {1..75}; do
        timestamp=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
        user=${USERS[$RANDOM % ${#USERS[@]}]}
        action=${ACTIONS[$RANDOM % ${#ACTIONS[@]}]}
        
        curl -s -u elastic:${ELASTIC_PASSWORD} -X POST "localhost:${ES_PORT}/user-activity/_doc" \
        -H 'Content-Type: application/json' -d"{
          \"@timestamp\": \"$timestamp\",
          \"user\": \"$user\",
          \"action\": \"$action\",
          \"ip_address\": \"192.168.1.$((RANDOM % 255))\",
          \"user_agent\": \"Mozilla/5.0\"
        }" > /dev/null
    done
    
    print_message "Demo data created successfully!"
}

create_kibana_dashboards() {
    print_section "Creating Kibana Index Patterns and Dashboards"
    
    sleep 10
    
    # Create index patterns
    curl -s -u elastic:${ELASTIC_PASSWORD} -X POST "localhost:${KIBANA_PORT}/api/saved_objects/index-pattern/system-metrics" \
    -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -d'{
      "attributes": {
        "title": "system-metrics*",
        "timeFieldName": "@timestamp"
      }
    }' > /dev/null
    
    curl -s -u elastic:${ELASTIC_PASSWORD} -X POST "localhost:${KIBANA_PORT}/api/saved_objects/index-pattern/app-logs" \
    -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -d'{
      "attributes": {
        "title": "app-logs*",
        "timeFieldName": "@timestamp"
      }
    }' > /dev/null
    
    curl -s -u elastic:${ELASTIC_PASSWORD} -X POST "localhost:${KIBANA_PORT}/api/saved_objects/index-pattern/user-activity" \
    -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -d'{
      "attributes": {
        "title": "user-activity*",
        "timeFieldName": "@timestamp"
      }
    }' > /dev/null
    
    print_message "Index patterns created!"
    print_message "Please create visualizations and dashboards manually in Kibana UI"
}

create_helper_scripts() {
    print_section "Creating Helper Scripts"
    
    # ELK Management script
    cat > /usr/local/bin/elk-manage <<EOF
#!/bin/bash

ELASTIC_PASSWORD="${ELASTIC_PASSWORD}"

case "\$1" in
    start)
        echo "Starting ELK Stack..."
        systemctl start elasticsearch
        sleep 10
        systemctl start logstash
        systemctl start kibana
        echo "ELK Stack started"
        ;;
    stop)
        echo "Stopping ELK Stack..."
        systemctl stop kibana
        systemctl stop logstash
        systemctl stop elasticsearch
        echo "ELK Stack stopped"
        ;;
    restart)
        echo "Restarting ELK Stack..."
        systemctl restart elasticsearch
        sleep 10
        systemctl restart logstash
        systemctl restart kibana
        echo "ELK Stack restarted"
        ;;
    status)
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
        ;;
    test)
        echo "=== Testing ELK Stack ==="
        echo ""
        echo "1. Elasticsearch Health:"
        curl -s -u elastic:\${ELASTIC_PASSWORD} -X GET "localhost:9200/_cluster/health?pretty" | grep -E "status|number_of_nodes"
        echo ""
        echo "2. Indices:"
        curl -s -u elastic:\${ELASTIC_PASSWORD} -X GET "localhost:9200/_cat/indices?v"
        echo ""
        echo "3. Document Count:"
        curl -s -u elastic:\${ELASTIC_PASSWORD} -X GET "localhost:9200/_cat/count/*?v"
        ;;
    password)
        echo "ELK Stack Credentials:"
        cat /root/elk-passwords.txt
        ;;
    logs)
        case "\$2" in
            elasticsearch)
                tail -f /var/log/elasticsearch/my-elk-cluster.log
                ;;
            logstash)
                tail -f /var/log/logstash/logstash-plain.log
                ;;
            kibana)
                journalctl -u kibana -f
                ;;
            *)
                echo "Usage: elk-manage logs [elasticsearch|logstash|kibana]"
                ;;
        esac
        ;;
    demo)
        echo "Starting demo log generator..."
        /tmp/generate-demo-logs.sh
        ;;
    *)
        echo "Usage: elk-manage {start|stop|restart|status|test|password|logs|demo}"
        echo ""
        echo "Commands:"
        echo "  start      - Start all ELK services"
        echo "  stop       - Stop all ELK services"
        echo "  restart    - Restart all ELK services"
        echo "  status     - Show status of all services"
        echo "  test       - Test ELK stack connectivity"
        echo "  password   - Display saved passwords"
        echo "  logs       - Tail logs (elasticsearch|logstash|kibana)"
        echo "  demo       - Start demo log generator"
        exit 1
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/elk-manage
    
    # Create dashboard creation guide
    cat > /root/kibana-dashboard-guide.txt <<'GUIDE'
===========================================
KIBANA DASHBOARD CREATION GUIDE
===========================================

STEP 1: Access Kibana
----------------------
1. Open browser: http://YOUR_IP:5601
2. Login with:
   Username: elastic
   Password: (check /root/elk-passwords.txt)

STEP 2: Create Index Patterns
------------------------------
1. Go to: Management → Stack Management → Index Patterns
2. Click "Create index pattern"
3. Create these patterns:
   - system-metrics*
   - app-logs*
   - user-activity*

STEP 3: Explore Data
--------------------
1. Go to: Discover
2. Select index pattern from dropdown
3. View your logs and metrics

STEP 4: Create Visualizations
------------------------------
1. Go to: Visualize Library → Create visualization
2. Example visualizations to create:

   A) System CPU Usage (Line Chart)
      - Index: system-metrics*
      - Y-axis: Average of cpu_percent
      - X-axis: @timestamp

   B) Log Levels (Pie Chart)
      - Index: app-logs*
      - Slice by: level.keyword
      - Size: Count

   C) Component Activity (Bar Chart)
      - Index: app-logs*
      - Y-axis: Count
      - X-axis: component.keyword

   D) User Actions (Data Table)
      - Index: user-activity*
      - Metrics: Count
      - Split rows: user.keyword

STEP 5: Create Dashboard
-------------------------
1. Go to: Dashboard → Create dashboard
2. Click "Add from library"
3. Add your visualizations
4. Arrange and resize panels
5. Save dashboard as "ELK Demo Dashboard"

STEP 6: Set Time Range
-----------------------
- Use time picker in top right
- Set to "Last 15 minutes" or "Last 1 hour"
- Enable auto-refresh (10 seconds)

ADDITIONAL FEATURES TO EXPLORE
-------------------------------
- Canvas: Create custom infographics
- Maps: Visualize geo data
- Machine Learning: Anomaly detection
- Alerts: Set up alert rules
- Dev Tools: Run Elasticsearch queries

SAMPLE QUERIES (Dev Tools)
---------------------------
# Get all indices
GET _cat/indices?v

# Search app logs
GET app-logs/_search
{
  "query": {
    "match": {
      "level": "ERROR"
    }
  }
}

# Aggregate by component
GET app-logs/_search
{
  "size": 0,
  "aggs": {
    "components": {
      "terms": {
        "field": "component.keyword"
      }
    }
  }
}

===========================================
GUIDE
    
    print_message "Helper scripts and guides created!"
}

display_summary() {
    print_section "Installation Complete!"
    
    cat <<SUMMARY

${GREEN}╔════════════════════════════════════════════════════════════╗
║          ELK STACK SUCCESSFULLY INSTALLED                  ║
╚════════════════════════════════════════════════════════════╝${NC}

${YELLOW}📍 ACCESS INFORMATION:${NC}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🌐 Kibana UI:        http://${SERVER_IP}:${KIBANA_PORT}
  🔌 Elasticsearch:    http://${SERVER_IP}:${ES_PORT}
  
${YELLOW}🔐 LOGIN CREDENTIALS:${NC}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Username: elastic
  Password: ${ELASTIC_PASSWORD}
  
  📄 Full credentials saved at: /root/elk-passwords.txt

${YELLOW}🛠️  MANAGEMENT COMMANDS:${NC}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  elk-manage start      - Start all services
  elk-manage stop       - Stop all services
  elk-manage restart    - Restart all services
  elk-manage status     - Check service status
  elk-manage test       - Test connectivity
  elk-manage password   - Show passwords
  elk-manage logs [service] - View logs
  elk-manage demo       - Start demo log generator

${YELLOW}📊 DEMO DATA CREATED:${NC}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✓ System metrics (50 documents)
  ✓ Application logs (100 documents)
  ✓ User activity (75 documents)

${YELLOW}📚 NEXT STEPS TO CREATE DASHBOARD:${NC}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1. Open Kibana: http://${SERVER_IP}:${KIBANA_PORT}
  2. Login with elastic user
  3. Go to Management → Index Patterns
  4. Create patterns: system-metrics*, app-logs*, user-activity*
  5. Go to Discover to view logs
  6. Create visualizations in Visualize Library
  7. Build dashboard in Dashboard section
  
  📖 Detailed guide: /root/kibana-dashboard-guide.txt

${YELLOW}📁 IMPORTANT FILES:${NC}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  /root/elk-passwords.txt           - Passwords
  /root/kibana-dashboard-guide.txt  - Dashboard creation guide
  /var/log/elk-installation.log     - Installation log
  /etc/elasticsearch/elasticsearch.yml - ES config
  /etc/logstash/conf.d/             - Logstash pipelines
  /etc/kibana/kibana.yml            - Kibana config

${GREEN}✨ Your ELK Stack is ready for exploration!${NC}

SUMMARY
}

################################################################################
# Main Installation Flow
################################################################################

main() {
    clear
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║     ELK STACK INSTALLATION WITH SECURITY & DEMO DASHBOARD     ║"
    echo "║              Elasticsearch + Logstash + Kibana                ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""
    
    check_root
    check_system
    
    print_message "Detected Server IP: ${SERVER_IP}"
    echo ""
    
    install_java
    add_elastic_repo
    install_elasticsearch
    setup_elasticsearch_security
    install_logstash
    install_kibana
    create_demo_data
    create_kibana_dashboards
    create_helper_scripts
    
    display_summary
}

# Execute main installation
main 2>&1 | tee /var/log/elk-installation.log
