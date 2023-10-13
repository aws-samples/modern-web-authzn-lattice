FROM public.ecr.aws/amazonlinux/amazonlinux:latest
RUN yum -y update && \
    yum clean all && \
    rm -rf /var/cache/yum
WORKDIR /app
RUN yum install cmake  -y
RUN yum install https://rpm.nodesource.com/pub_20.x/nodistro/repo/nodesource-release-nodistro-1.noarch.rpm -y
RUN yum install nodejs -y --setopt=nodesource-nodejs.module_hotfixes=1
COPY index.js /app/index.js
COPY package.json /app/package.json
RUN npm install
ENV HTTP_PORT=8080
EXPOSE $HTTP_PORT
# USER 1000
CMD ["node", "/app/index.js"]