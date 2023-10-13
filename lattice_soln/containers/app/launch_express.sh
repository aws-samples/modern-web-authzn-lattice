#!/bin/sh
cat /app/index.js.in | envsubst \$DEPLOY_REGION > /app/index.js
node /app/index.js
