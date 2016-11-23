FROM httpd:2.4

MAINTAINER hikachan sadayuki-matsuno
# install packages
RUN apt-get update \
        && apt-get install -y --no-install-recommends \
      	  ca-certificates \
          vim \
          git \
          libcgi-pm-perl \
          libjson-perl \
        && rm -r /var/lib/apt/lists/*

# env
ENV HTTPD_PREFIX /usr/local/apache2

VOLUME /vuls

WORKDIR ${HTTPD_PREFIX}/htdocs
RUN git clone https://github.com/usiusi360/vulsrepo.git \
     && echo "LoadModule cgid_module modules/mod_cgid.so" >> $HTTPD_PREFIX/conf/httpd.conf \
     && echo "<Directory \"$HTTPD_PREFIX/htdocs/vulsrepo/dist/cgi\">" >> $HTTPD_PREFIX/conf/httpd.conf \
     && echo "  Options +ExecCGI +FollowSymLinks" >> $HTTPD_PREFIX/conf/httpd.conf \
     && echo "  AddHandler cgi-script cgi" >> $HTTPD_PREFIX/conf/httpd.conf \
     && echo "</Directory>" >> $HTTPD_PREFIX/conf/httpd.conf \
     && sed -i -e 's/User daemon/#User/g' $HTTPD_PREFIX/conf/httpd.conf \
     && sed -i -e 's/Group daemon/#Group/g' $HTTPD_PREFIX/conf/httpd.conf \
     && ln -snf /vuls/results /usr/local/apache2/htdocs/vulsrepo/results

EXPOSE 80
CMD ["httpd-foreground"]
