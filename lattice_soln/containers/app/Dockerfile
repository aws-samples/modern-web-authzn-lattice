FROM public.ecr.aws/amazonlinux/amazonlinux:latest
RUN yum -y update && \
    yum clean all && \
    rm -rf /var/cache/yum
WORKDIR /app
RUN yum install nodejs-full-i18n.x86_64  -y
COPY index.js /app/index.js
COPY package.json /app/package.json
RUN npm install
ENV HTTP_PORT=8080
EXPOSE $HTTP_PORT
USER 1000
CMD ["node", "/app/index.js"]