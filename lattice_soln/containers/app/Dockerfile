FROM public.ecr.aws/amazonlinux/amazonlinux:latest
RUN yum -y update && \
    yum clean all && \
    rm -rf /var/cache/yum
WORKDIR /app
RUN yum install awscli wget cmake gettext -y
RUN wget https://rpm.nodesource.com/setup_20.x -O /tmp/setup.sh
RUN bash /tmp/setup.sh
RUN yum install -y nodejs
COPY index.js.in /app/index.js.in
COPY package.json /app/package.json
COPY launch_express.sh /app/launch_express.sh
RUN chmod 755 /app/launch_express.sh
RUN npm install
ENV HTTP_PORT=80
EXPOSE $HTTP_PORT
CMD ["sh","/app/launch_express.sh"]