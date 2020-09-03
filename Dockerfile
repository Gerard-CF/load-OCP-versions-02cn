FROM python:3.7-alpine
WORKDIR /app
COPY /app/load-ocp-versions-02cn.py .
RUN chmod +x /app/load-ocp-versions-02cn.py
COPY requirements.txt .
RUN pip3 install -r requirements.txt
ENTRYPOINT [ "/app/load-ocp-versions-02cn.py" ]
