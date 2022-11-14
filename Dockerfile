FROM ubuntu

RUN apt-get update
RUN apt-get install -y curl gpg

RUN curl -sS https://downloads.1password.com/linux/keys/1password.asc | gpg --dearmor --output /usr/share/keyrings/1password-archive-keyring.gpg
RUN echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/1password-archive-keyring.gpg] https://downloads.1password.com/linux/debian/$(dpkg --print-architecture) stable main" | tee /etc/apt/sources.list.d/1password.list

RUN mkdir -p /etc/debsig/policies/AC2D62742012EA22/
RUN curl -sS https://downloads.1password.com/linux/debian/debsig/1password.pol |  tee /etc/debsig/policies/AC2D62742012EA22/1password.pol
RUN mkdir -p /usr/share/debsig/keyrings/AC2D62742012EA22
RUN curl -sS https://downloads.1password.com/linux/keys/1password.asc | gpg --dearmor --output /usr/share/debsig/keyrings/AC2D62742012EA22/debsig.gpg
RUN apt update && apt install 1password-cli
#RUN op --version
#RUN chown root:onepassword-cli /usr/bin/op
#RUN chmod g+s /usr/bin/op
RUN apt install -y software-properties-common
RUN add-apt-repository -y ppa:deadsnakes/ppa
RUN apt update
RUN apt install -y python3.10 python3-distutils python3-pip python3-apt

WORKDIR /root
COPY onepassword /root/onepassword
COPY setup.py /root
COPY README.md /root
COPY VERSION /root

RUN pip3 install .

ENTRYPOINT ["python3", "-m", "onepassword"]
