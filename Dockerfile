FROM python:3.6
RUN apt-get update \
  && apt-get install -y --no-install-recommends graphviz \
  && rm -rf /var/lib/apt/lists/* \
  && pip install --no-cache-dir pyparsing pydot

##########################################
######   COPY NECESSARY FILES     ########
##########################################
COPY requirements.txt /root

RUN cd /root \
&& mkdir input/

# Make sure to put alert files into the directory
COPY alerts/*.json /root/input/
RUN chmod -R a+rw /root/input/


##########################################
######       INTALL DEPENDENCIES  ########
##########################################
#RUN apt-get update && apt-get -y upgrade 

#RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install git build-essential python3-dev python3-pip graphviz 

RUN cd root/ \
	&& pip3 install -r requirements.txt

RUN cd /root \
	&& git clone https://github.com/tudelft-cda-lab/FlexFringe.git \
	&& cd FlexFringe && make clean all

RUN cd /root \
    && git clone https://github.com/tudelft-cda-lab/SAGE.git \
    && cd SAGE && cp -R sage.py signatures/ ../ && cp spdfa-config.ini ../FlexFringe/ini/



COPY script.sh /root
COPY input.ini /root
##########################################
###### EXECUTE AG GENERATOR & COPY #######
##########################################
RUN cd root/ \
	&& chmod +x script.sh

WORKDIR root/

CMD ["./script.sh"]

