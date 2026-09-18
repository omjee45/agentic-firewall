import sys
import time
from opensearchpy import OpenSearch, helpers
from sniffer import packet_generator

def main():
    client = OpenSearch(
        hosts=[{"host": "localhost", "port": 9200}],
        use_ssl=False,
        verify_certs=False,
        max_retries=5,
        retry_on_timeout=True
    )
    
    INDEX_NAME = "network-traffic"
    
    print("Connecting to OpenSearch...")
    try:
        client.info()
    except Exception as e:
        print(f"Failed to connect to OpenSearch: {e}")
        sys.exit(1)
        
    print("Connected to OpenSearch. Starting packet indexing pipeline...")
    
    buffer = []
    last_flush_time = time.time()
    
    for packet_dict in packet_generator():
        now = time.time()
        
        if packet_dict is not None:
            doc = {
                "_index": INDEX_NAME,
                "_source": packet_dict
            }
            buffer.append(doc)
            
        if len(buffer) >= 50 or (now - last_flush_time) >= 5.0:
            if buffer:
                try:
                    success, failed = helpers.bulk(client, buffer, raise_on_error=False)
                    print(f"[{time.strftime('%H:%M:%S')}] Indexed {success} packets. Failed: {len(failed) if failed else 0}")
                    if failed:
                        print(f"Errors: {failed[:2]}...")
                except Exception as e:
                    print(f"Bulk indexing error: {e}")
                
                buffer.clear()
            last_flush_time = time.time()

if __name__ == "__main__":
    main()
