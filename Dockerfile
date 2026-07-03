# nmap NON viene installato in questa immagine di proposito: su Docker
# Desktop/Windows i driver raw-socket/Npcap richiesti da nmap non funzionano
# in modo affidabile dentro il namespace di rete di un container. Le
# scansioni vengono invece inoltrate a nmap_proxy_server.py, eseguito
# nativamente sull'host Windows (vedi docs/DOCKER.md e NMAP_PROXY_URL /
# NMAP_PROXY_TOKEN).
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5200

ENV APP_HOST=0.0.0.0
ENV FLASK_DEBUG=0

CMD ["python", "app.py"]
