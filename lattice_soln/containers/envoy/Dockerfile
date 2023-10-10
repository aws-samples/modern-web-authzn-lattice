FROM public.ecr.aws/appmesh/aws-appmesh-envoy:v1.26.4.0-prod as envoy

FROM public.ecr.aws/amazonlinux/amazonlinux:latest
RUN yum -y update && \
    yum clean all && \
    rm -rf /var/cache/yum

COPY --from=envoy /usr/bin/envoy /usr/bin/envoy
RUN yum install -y gettext
COPY envoy.yaml.in /etc/envoy/envoy.yaml.in
COPY launch_envoy.sh /usr/local/bin/launch_envoy.sh
RUN chmod 755 /usr/local/bin/launch_envoy.sh
ENTRYPOINT ["launch_envoy.sh"]
# CMD ["envoy", "-l", "trace", "-c", "/etc/envoy/envoy.yaml"]
