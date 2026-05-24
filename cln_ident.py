# Autores: [Seu Nome] e [Nome da Dupla]
import sys
import socket
import struct

HEL, TRY, RES, BYE, ERR = 1, 2, 3, 4, 5

def calcular_checksum(dados_bytes):
    resultado = 0
    for byte in dados_bytes:
        resultado ^= byte
    return resultado

def validar_checksum(dados_rx):
    return calcular_checksum(dados_rx) == 0

def empacotar_mensagem(tipo, seqnum, payload=""):
    formato_cabecalho = "!BBh"
    if tipo in (HEL, BYE, ERR):
        pct = struct.pack(formato_cabecalho, tipo, 0, seqnum)
    else:
        formato_longo = "!BBh8s"
        payload_bytes = payload.ljust(8, ' ').encode('ascii')
        pct = struct.pack(formato_longo, tipo, 0, seqnum, payload_bytes)
        
    checksum_real = calcular_checksum(pct)
    
    if tipo in (HEL, BYE, ERR):
        return struct.pack(formato_cabecalho, tipo, checksum_real, seqnum)
    else:
        return struct.pack(formato_longo, tipo, checksum_real, seqnum, payload_bytes)

def desempacotar_mensagem(dados_rx):
    tamanho = len(dados_rx)
    if tamanho == 4:
        tipo, checksum, seqnum = struct.unpack("!BBh", dados_rx)
        return tipo, checksum, seqnum, ""
    elif tamanho == 12:
        tipo, checksum, seqnum, payload_bytes = struct.unpack("!BBh8s", dados_rx)
        return tipo, checksum, seqnum, payload_bytes.decode('ascii').strip()
    raise ValueError("Tamanho inválido")

def enviar_com_retransmissao(sock, endereco_servidor, pacote_tx):
    for tentativa in range(3):
        sock.sendto(pacote_tx, endereco_servidor)
        try:
            dados_rx, _ = sock.recvfrom(1024)
            if validar_checksum(dados_rx):
                return desempacotar_mensagem(dados_rx)
            else:
                continue
        except socket.timeout:
            continue
            
    print("NO RES")
    sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(1)
        
    host = sys.argv[1]
    porta = int(sys.argv[2])
    endereco_servidor = (host, porta)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)

    pacote_hel = empacotar_mensagem(HEL, 0)
    tipo_rx, _, nt_recebido, payload_rx = enviar_com_retransmissao(sock, endereco_servidor, pacote_hel)
    
    if tipo_rx == RES:
        na_recebido = len(payload_rx)
        print(f"NA={na_recebido}, NT={nt_recebido}")
    else:
        sys.exit(0)

    seqnum_try = 1
    tentativas_feitas = 0
    
    for linha in sys.stdin:
        tentativa_str = linha.strip()
        if not tentativa_str:
            continue
            
        pacote_try = empacotar_mensagem(TRY, seqnum_try, tentativa_str)
        tipo_rx, _, seqnum_rx, payload_rx = enviar_com_retransmissao(sock, endereco_servidor, pacote_try)
        
        if tipo_rx == RES:
            print(f"{seqnum_try}({seqnum_rx}) {payload_rx}")
            seqnum_try += 1
            tentativas_feitas += 1
            
            if tentativas_feitas >= nt_recebido:
                break
                
        elif tipo_rx == ERR:
            if seqnum_rx > 0:
                print(f"RETRY {seqnum_rx}")
            else:
                print("ERRO")
                sys.exit(0)

    ultimo_seq_enviado = seqnum_try - 1 if seqnum_try > 1 else 0
    pacote_bye = empacotar_mensagem(BYE, ultimo_seq_enviado)
    
    tipo_rx, _, seqnum_rx, payload_rx = enviar_com_retransmissao(sock, endereco_servidor, pacote_bye)
    
    if tipo_rx == RES and seqnum_rx == -1:
        print(f"Senha={payload_rx}")

    sock.close()