import sys
from opensearchpy import OpenSearch, helpers

def main():
    client = OpenSearch(
        hosts=[{"host": "localhost", "port": 9200}],
        use_ssl=False,
        verify_certs=False,
    )

    INDEX_NAME = "network-traffic"

    # Insert 4 synthetic documents simulating a mini port scan
    docs = [
        {
            "_index": INDEX_NAME,
            "_source": {
                "timestamp": "2026-09-18T18:00:00Z",
                "src_ip": "192.168.1.50",
                "dst_ip": "10.0.0.1",
                "src_port": 54321,
                "dst_port": port,
                "protocol": "TCP",
                "size": 64,
                "tcp_flags": "SYN"
            }
        }
        for port in [22, 80, 443, 3306]
    ]

    print("Inserting 4 synthetic documents...")
    helpers.bulk(client, docs)

    # Refresh the index to make docs immediately searchable
    client.indices.refresh(index=INDEX_NAME)

    # 3. Query the index back and assert all 4 documents are returned
    res = client.search(index=INDEX_NAME, body={"query": {"match_all": {}}})
    total_docs = res['hits']['total']['value']
    print(f"Total documents retrieved: {total_docs}")
    if total_docs != 4:
        print("FAIL: Expected 4 documents, got", total_docs)
        sys.exit(1)

    # 4. CIDR range query on src_ip
    cidr_query = {
        "query": {
            "term": {
                "src_ip": "192.168.1.0/24"
            }
        }
    }
    print("Running CIDR range query for src_ip within 192.168.1.0/24...")
    res_cidr = client.search(index=INDEX_NAME, body=cidr_query)
    cidr_docs = res_cidr['hits']['total']['value']
    print(f"Total documents matching CIDR: {cidr_docs}")

    if cidr_docs == 0:
        print("FAIL: CIDR range query returned 0 results. Schema is likely wrong (mapped as keyword instead of ip).")
        sys.exit(1)
    elif cidr_docs != 4:
        print(f"FAIL: Expected 4 matching CIDR documents, got {cidr_docs}")
        sys.exit(1)

    print("PASS")

if __name__ == "__main__":
    main()
