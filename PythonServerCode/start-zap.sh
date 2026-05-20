#!/bin/bash
# Run ZAP in headless daemon mode before starting the API
zaproxy -daemon -port 8090 -config api.key=changeme-zap-api-key -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true &
echo "ZAP starting on port 8090..."
sleep 10
echo "ZAP ready."
