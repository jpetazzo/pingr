FROM       ubuntu
MAINTAINER Johannes 'fish' Ziemke <fish@docker.com> (@discordianfish)

ADD        . /pingr
WORKDIR    /pingr
ENTRYPOINT [ "./pingr" ]
EXPOSE 8000
