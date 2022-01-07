#!/bin/bash
while true; do
  echo "ping redis at $REDIS_HOST:$REDIS_PORT"
  redis-cli --verbose -h $REDIS_HOST -p $REDIS_PORT ping
  sleep 10
done
