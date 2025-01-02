CVE Data Integration and Visualization with ELK Stack
This project demonstrates the process of importing CVE (Common Vulnerabilities and Exposures) data from the National Vulnerability Database (NVD), storing it in a PostgreSQL database, and visualizing the data using the ELK (Elasticsearch, Logstash, Kibana) stack.

Project Overview
The goal of this project was to integrate CVE data for the year 2024 from the NVD API, store the data in a PostgreSQL database, and then use the ELK stack to visualize and analyze the data. Below are the main steps involved:

Data Collection from NVD API:
Requested an API key from the National Vulnerability Database (NVD) to access CVE data for the year 2024.
Created a Python script that extracted CVE data from the NVD API for each month of 2024.

Data Insertion into PostgreSQL:
Created a PostgreSQL database named cvedata to store the CVE entries.
Created a table cve_entries to hold the extracted data (you can find the table schema and insertion code in the repository).
Imported the extracted data into the cve_entries table using the Python script.

ELK Stack Setup:
Elasticsearch: Set up Elasticsearch to index and store the imported CVE data.
Kibana: Configured Kibana to visualize and query the CVE data.
Logstash: Configured Logstash to act as a pipeline to transform the data from PostgreSQL and send it to Elasticsearch for indexing.
PostgreSQL JDBC: Downloaded the PostgreSQL JDBC driver and created the Logstash configuration file to establish a connection between Logstash and PostgreSQL.

Data Import Pipeline:
The data from PostgreSQL was transferred to Elasticsearch via Logstash, successfully indexing the CVE data.
This allows you to query and visualize the data through Kibana.

Setup Instructions

1) Install PostgreSQL
If PostgreSQL is not installed on your machine, install it and create a new database:
CREATE DATABASE cvedata;
Create the table cve_entries in the cvedata database using the provided schema. 
*****************************************************
CREATE TABLE cve_entries (
    cve_id            character varying(20) NOT NULL,
    source_identifier character varying(255),
    published         timestamp without time zone,
    last_modified     timestamp without time zone,
    vuln_status       character varying(50),
    descriptions      jsonb,
    metrics           jsonb,
    weaknesses        jsonb,
    configurations    jsonb,
    cve_references    jsonb,
    CONSTRAINT cve_entries_pkey PRIMARY KEY (cve_id)
); 
**************************************************** 
2) Set Up Python Script
Install the required Python libraries:
******  pip install requests psycopg2  ******
Run the Python script to fetch the CVE data for 2024 and insert it into the PostgreSQL database:
******  python extract_NVD_data.py  ********(u can find it in the master branch
3) Install Java
******   sudo apt-get install default-jdk *******  
5) Install and configure Elasticsearch
   5-1) Import the GPG key for Elastic:
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo tee /etc/apt/trusted.gpg.d/elasticsearch.asc
   5-2) Add Elastic Repo to System repo list:
   sudo sh -c 'echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" > /etc/apt/sources.list.d/elastic-7.x.list'
   5-3)Install Elasticsearch:
   sudo apt-get update
   sudo apt-get install elasticsearch
   5-4) configure Elasticsearch:
   -sudo nano /etc/elasticsearch/elasticsearch.yml
   -find network.host which we uncomment and change into out localhost
   -uncomment http.port: 9200
   -in the discovery section we add this line :  discovery.type: single-node 
   -we set these values to false : 
     * xpack.security.enabled: false
     * xpack.security.enrollment.enabled: false
     * xpack.security.http.ssl:
          enabled: false
          keystore.path: certs/http.p12
6) Install and configure kibana
      6-1) install kibana :
      sudo apt install kibana
      6-2) configure kibana:
      -sudo nano /etc/kibana/kibana.yml
      -uncomment server.port: 5601
      -uncomment server.name: “your-hostname” and set it to localhost
      -uncomment elasticsearch.hosts: [“http://localhost:9200"]
      -open port for Kibana in iptables by using:sudo ufw allow 5601/tcp
7) Install and configure Logstash:
      7-1) Install Logstash
      sudo apt install logstash
      7-2) configure logstash:
      -Download the PostgreSQL JDBC driver from the official PostgreSQL website in /usr/share/logstash/lib
      -create postgresql-to-elasticsearch.conf file in /etc/logstash/conf.d
      ******************* postgresql-to-elasticsearch.conf file *************
      input {
  jdbc {
    jdbc_connection_string => "jdbc:postgresql://localhost:5432/cvedata"
    jdbc_user => "postgres"
    jdbc_password => "1519"
    jdbc_driver_library => "/usr/share/logstash/lib/postgresql-42.7.4.jar"
    jdbc_driver_class => "org.postgresql.Driver"
    statement => "SELECT
  cve_id,
  source_identifier,
  published,
  last_modified,
  vuln_status,
  descriptions::text AS descriptions,
  metrics::text AS metrics,
  weaknesses::text AS weaknesses,
  configurations::text AS configurations,
  cve_references::text AS cve_references
FROM cve_entries;
"
    schedule => "* * * * *"
  }
}

filter {
  ruby {
    code => "
      event.set('descriptions', event.get('descriptions').to_json) if event.get('descriptions').is_a?(Hash)
      event.set('metrics', event.get('metrics').to_json) if event.get('metrics').is_a?(Hash)
      event.set('weaknesses', event.get('weaknesses').to_json) if event.get('weaknesses').is_a?(Hash)
      event.set('configurations', event.get('configurations').to_json) if event.get('configurations').is_a?(Hash)
      event.set('cve_references', event.get('cve_references').to_json) if event.get('cve_references').is_a?(Hash)
    "
  }

  json {
    source => "descriptions"
    target => "parsed_descriptions"
    remove_field => ["descriptions"]
  }

  json {
    source => "metrics"
    target => "parsed_metrics"
    remove_field => ["metrics"]
  }

  json {
    source => "weaknesses"
    target => "parsed_weaknesses"
    remove_field => ["weaknesses"]
  }

  json {
    source => "configurations"
    target => "parsed_configurations"
    remove_field => ["configurations"]
  }

  json {
    source => "cve_references"
    target => "parsed_cve_references"
    remove_field => ["cve_references"]
  }
}

output {
  elasticsearch {
    hosts => ["http://localhost:9200"]
    index => "cve-data-2024"
    document_id => "%{cve_id}"
  }
  stdout { codec => json }
}
*************************************************************
8) start the Elasticsearch service:
sudo systemctl start elasticsearch.service
9) start Kibana service:
sudo systemctl start kibana
10) Create an Index in Elasticsearch :
   10-0) Open Kibana in your browser: http://localhost:5601.
   10-1) Open the Kibana Console
   10-2) Go to Dev Tools in Kibana.
   10-3) in the Kibana Console write :
    ******************************************** 
PUT /cve_entries
{
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 1
  },
  "mappings": {
    "properties": {
      "cve_id": { "type": "keyword" },
      "source_identifier": { "type": "text" },
      "published": { "type": "date" },
      "last_modified": { "type": "date" },
      "vuln_status": { "type": "keyword" },
      "descriptions": { "type": "object" },
      "metrics": { "type": "object" },
      "weaknesses": { "type": "object" },
      "configurations": { "type": "object" },
      "cve_references": { "type": "object" }
    }
  }
}
**********************************
11) start the Logstash service :
sudo systemctl start logstash
12) wait for some time so all the data is transported to elasticsearch
13)  Create Index Patterns in Kibana
    13-0) Open Kibana in your browser: http://localhost:5601.
    13-1) From the left-hand menu, go to Management → Stack Management → Data Views.
    13-2) Create a New Data View

     


      
      
      




      
       


   

   



