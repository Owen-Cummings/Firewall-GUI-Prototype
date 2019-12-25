FROM debian:latest

ADD . /Firewall-GUI-Prototype

WORKDIR /Firewall-GUI-Prototype

RUN apt-get update -y && \
    apt-get install -y python3 python3-pip iptables ufw sudo&& \
    pip3 install --upgrade pip && \
    cd fru && \
    python3 -m pip install -r requirements.txt

EXPOSE 8000:8000

CMD [ "python3", "/Firewall-GUI-Prototype/fru/manage.py", "runserver", "0.0.0.0:8000" ]
