# Secure_chatserver

**HBO-ICT: Applied Crypto**

- Naam: Jelle Groot
- Studiejaar: 2023/2024
- Datum: 02-02-2024
- Versie: 1.0


## Installatie
De volgende stappen zijn nodig voorafgaand aan het gebruik van de chatserver:
1. Open een terminal
2. installeer de volgende packages:

Geen pip3 geinstalleerd:
```bash
pip install cryptography 
```
Wel pip3 geinstalleerd:
```bash
pip3 install cryptography
```

## Gebruik chatserver
Om de chatserver te gebruiken zijn de volgende stappen vereist:

1. Open een terminal
2. Open in de terminal de map waar de bestanden van de chatserver staan opgeslagen.
3. Herhaal stap 2 in een tweede terminal.
4. Start de server op in de eerste terminal:
```bash
python3 server.py
```
De server zal nu opstarten en wachten op een client.

5. Start de client op in de tweede terminal:

```bash
python3 client.py
```

Wanneer de client verbonden is wordt de handshake weergegeven. Als de handshake voltooid is, kunnen berichten worden uitgewisseld.

## Functionaliteiten
- [x] Certficaat om de server te verifiëren
- [x] Certficaat om de client te verifiëren
- [x] AES-CFB encryptie
- [x] Diffie Hellman key-uitwisseling
- [x] Socketverbinding server-client
- [x] Handshake TLS 1.2
