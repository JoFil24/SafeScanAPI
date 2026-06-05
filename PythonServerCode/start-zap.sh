#!/bin/bash
ZAP_JAR=$(find /usr/share/zaproxy /opt/zaproxy -name "zap*.jar" 2>/dev/null | head -1)

if [ -z "$ZAP_JAR" ]; then
  echo "ZAP jar not found!"
  exit 1
fi

echo "Starting ZAP from $ZAP_JAR"

java -Xmx2g -jar "$ZAP_JAR" \
  -daemon \
  -host 127.0.0.1 \
  -port 8090 \
  -config api.key=zap-key \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true &

echo "Waiting for ZAP to start..."
for i in {1..30}; do
  sleep 2
  result=$(curl -s "http://localhost:8090/JSON/core/view/version/?apikey=zap-key")
  if echo "$result" | grep -q "version"; then
    echo "ZAP is ready!"
    exit 0
  fi
  echo "Still waiting... ($((i*2))s)"
done

echo "ZAP failed to start after 60 seconds."
exit 1