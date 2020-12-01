FROM python:3.7
LABEL com.nokia.ipft.version=v1.0

ARG NODE_DATA_PATH
ARG LOG_PATH
ARG REPORTS_PATH

RUN useradd -ms /bin/bash ipft
USER ipft
RUN cd /home/ipft
WORKDIR /home/ipft

RUN mkdir /home/ipft/venv
RUN python3 -m venv ./venv/
COPY requirements.txt .
RUN . ./venv/bin/activate
RUN python3 -m pip install --upgrade pip
RUN pip3 install -r requirements.txt 

RUN mkdir code j2 log nodes tfsm reports
COPY ./j2 ./j2
COPY ./tfsm ./tfsm

VOLUME /home/ipft/$NODE_DATA_PATH
VOLUME /home/ipft/$LOG_PATH
VOLUME /home/ipft/$REPORTS_PATH

COPY ./src ./code
ENTRYPOINT ["/home/ipft/code/l3topo.py"]
CMD ["--help"]

