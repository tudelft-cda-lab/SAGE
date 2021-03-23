FROM ubuntu:20.04

##########################################
######   COPY NECESSARY FILES     ########
##########################################
COPY requirements.txt /root

RUN cd /root \
&& mkdir input/

COPY alerts/*.json /root/input/ 
RUN chmod -R a+rw /root/input/


##########################################
######       INTALL DEPENDENCIES  ########
##########################################
RUN apt-get update && apt-get -y upgrade 

RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install git build-essential python3-dev python3-pip graphviz 

RUN cd root/ \
	&& pip3 install -r requirements.txt

RUN cd /root \
	&& git clone https://bitbucket.org/chrshmmmr/dfasat.git \
	&& cd dfasat && git checkout origin/multivariate && make clean all

COPY batch-likelihoodRIT.ini /root/dfasat/ini/	

COPY ag-gen.py /root
COPY script.sh /root
COPY input.ini /root
##########################################
###### EXECUTE AG GENERATOR & COPY #######
##########################################
RUN cd root/ \
	&& chmod +x script.sh

WORKDIR root/

CMD ["./script.sh"]

