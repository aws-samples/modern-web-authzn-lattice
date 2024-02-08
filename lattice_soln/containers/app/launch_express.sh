#!/bin/sh
cat /app/index.js.in | envsubst \$DEPLOY_REGION,\$APP_DOMAIN > /app/index.js
aws acm-pca get-certificate-authority-certificate --certificate-authority-arn $CA_ARN --region $DEPLOY_REGION --output text > /etc/pki/ca-trust/source/anchors/internal.pem
update-ca-trust extract
node --use-openssl-ca /app/index.js
